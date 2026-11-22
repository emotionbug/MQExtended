use std::{
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::{self, ExitCode},
};

use mqx_server::{LogConfig, startup_log};

pub(crate) const TERMINATING: &str = "mosquitto version 2.1.4 terminating";

#[derive(Debug)]
pub(crate) struct StartupError {
    pub(crate) code: ExitCode,
    pub(crate) message: String,
}

impl StartupError {
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: ExitCode::from(3), // MOSQ_ERR_INVAL
            message: message.into(),
        }
    }

    fn errno(message: impl Into<String>) -> Self {
        Self {
            code: ExitCode::from(14), // MOSQ_ERR_ERRNO
            message: message.into(),
        }
    }
}

// Mosquitto src/mosquitto.c: drop_privileges and print_pwname. Configuration
// has already been read, but listeners and all sensitive files open later.
#[cfg(unix)]
pub(crate) fn drop_privileges(user: &str, log: &LogConfig) -> Result<(), StartupError> {
    use nix::unistd::{Gid, Uid, User, getegid, geteuid, initgroups, setgid, setuid};
    use std::ffi::CString;

    if env::var_os("SNAP_NAME").is_some_and(|name| name == "mosquitto") {
        return Ok(());
    }
    let was_root = geteuid().is_root();
    if was_root {
        match (env::var_os("PGID"), env::var_os("PUID")) {
            (None, None) if user != "root" => {
                let account = User::from_name(user).ok().flatten();
                let account = match account {
                    Some(account) => account,
                    None if user == "mosquitto" => {
                        startup_log(
                            log,
                            format_args!(
                                "Warning: Unable to drop privileges to '{user}' because this user does not exist. Trying 'nobody' instead."
                            ),
                        );
                        User::from_name("nobody").ok().flatten().ok_or_else(|| {
                            StartupError::errno("Error: Unable to drop privileges to 'nobody'.")
                        })?
                    }
                    None => {
                        return Err(StartupError::invalid(format!(
                            "Error: Unable to drop privileges to '{user}' because this user does not exist."
                        )));
                    }
                };
                // Even when nobody is chosen, Mosquitto passes the original name.
                let group_user =
                    CString::new(user).expect("a configured Unix passwd name has no NUL");
                initgroups(&group_user, account.gid).map_err(|e| privilege_error("groups", e))?;
                setgid(account.gid).map_err(|e| privilege_error("gid", e))?;
                setuid(account.uid).map_err(|e| privilege_error("uid", e))?;
            }
            (pgid, puid) => {
                if let Some(value) = pgid
                    && let id = check_id(&value, "PGID")?
                    && id != 0
                {
                    setgid(Gid::from_raw(id)).map_err(|e| privilege_error("gid", e))?;
                }
                if let Some(value) = puid
                    && let id = check_id(&value, "PUID")?
                    && id != 0
                {
                    setuid(Uid::from_raw(id)).map_err(|e| privilege_error("uid", e))?;
                }
            }
        }
    }
    let uid = geteuid();
    if let Ok(Some(account)) = User::from_uid(uid) {
        startup_log(
            log,
            format_args!("Info: running mosquitto as user: {}.", account.name),
        );
    } else {
        startup_log(
            log,
            format_args!(
                "Info: running mosquitto as user id: {}.",
                uid.as_raw() as i32
            ),
        );
    }
    if was_root && (uid.is_root() || getegid().as_raw() == 0) {
        startup_log(
            log,
            format_args!("Warning: Mosquitto should not be run as root/administrator."),
        );
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn drop_privileges(_: &str, _: &LogConfig) -> Result<(), StartupError> {
    Ok(())
}

#[cfg(unix)]
fn privilege_error(operation: &str, source: nix::errno::Errno) -> StartupError {
    StartupError::errno(format!(
        "Error setting {operation} whilst dropping privileges: {}.",
        source.desc()
    ))
}

// Mosquitto src/mosquitto.c: check_uid uses strtol, so signs and leading
// whitespace are accepted but trailing characters and signed-long overflow are not.
#[cfg(unix)]
fn check_id(value: &std::ffi::OsStr, name: &str) -> Result<u32, StartupError> {
    let id = parse_long(value, 10).ok_or_else(|| {
        StartupError::invalid(format!(
            "Error: {name} not a valid ID '{}'",
            value.to_string_lossy()
        ))
    })?;
    if id < 0 {
        return Err(StartupError::invalid(format!(
            "Error: {name} must not be negative"
        )));
    }
    u32::try_from(id)
        .ok()
        .filter(|&id| id <= i32::MAX as u32)
        .ok_or_else(|| {
            StartupError::invalid(format!("Error: {name} must not be less than {}", i32::MAX))
        })
}

#[cfg(unix)]
fn parse_long(value: &std::ffi::OsStr, radix: u32) -> Option<nix::libc::c_long> {
    let value = value
        .to_str()?
        .trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']);
    nix::libc::c_long::from_str_radix(value, radix).ok()
}

// Mosquitto src/mosquitto.c: set_umask, before daemonisation and pid__write.
#[cfg(unix)]
pub(crate) fn set_umask() -> Result<(), StartupError> {
    use nix::sys::stat::{Mode, umask};

    if let Some(value) = env::var_os("UMASK_SET") {
        let mask = parse_umask(&value)?;
        umask(Mode::from_bits_truncate(mask.into()));
    }
    Ok(())
}

#[cfg(unix)]
fn parse_umask(value: &std::ffi::OsStr) -> Result<u16, StartupError> {
    let mask = parse_long(value, 8).ok_or_else(|| {
        StartupError::invalid("Error: UMASK_SET environment variable not a valid octal number.")
    })?;
    if !(0..=0o777).contains(&mask) {
        return Err(StartupError::invalid(
            "Error: UMASK_SET environment variable out of range.",
        ));
    }
    Ok(mask as u16)
}

#[cfg(not(unix))]
pub(crate) fn set_umask() -> Result<(), StartupError> {
    Ok(())
}

// Mosquitto src/mosquitto.c: mosquitto__daemonise. Like that implementation,
// don't change cwd or reset the umask, and exit successfully in the parent.
// This must run before the Tokio runtime, logging subscriber or worker threads.
#[cfg(unix)]
pub(crate) fn daemonise(_: &LogConfig) -> Result<(), StartupError> {
    use nix::unistd::{dup2_stderr, dup2_stdin, dup2_stdout, setsid};

    match fork::fork().map_err(|e| daemon_error("Error in fork", e))? {
        fork::Fork::Parent(_) => process::exit(0),
        fork::Fork::Child => (),
    }
    setsid().map_err(|e| daemon_error("Error in setsid", e.into()))?;
    let redirect = |name, read, dup: fn(fs::File) -> nix::Result<()>| {
        fs::OpenOptions::new()
            .read(read)
            .write(!read)
            .open("/dev/null")
            .and_then(|file| dup(file).map_err(Into::into))
            .map_err(|e| daemon_error(&format!("Error whilst daemonising ({name})"), e))
    };
    redirect("stdin", true, dup2_stdin)?;
    redirect("stdout", false, dup2_stdout)?;
    redirect("stderr", false, dup2_stderr)
}

#[cfg(unix)]
fn daemon_error(message: &str, source: io::Error) -> StartupError {
    let detail = source.raw_os_error().map_or("Unknown error", |code| {
        nix::errno::Errno::from_raw(code).desc()
    });
    StartupError {
        code: ExitCode::FAILURE,
        message: format!("{message}: {detail}"),
    }
}

#[cfg(not(unix))]
pub(crate) fn daemonise(log: &LogConfig) -> Result<(), StartupError> {
    startup_log(
        log,
        format_args!("Warning: Can't start in daemon mode in Windows."),
    );
    Ok(())
}

pub(crate) struct PidFile(PathBuf);

impl PidFile {
    // Mosquitto src/mosquitto.c: pid__write, and libcommon/file_common.c:
    // mosquitto_fopen(..., restrict_read=false) truncates or creates with 0666
    // filtered by the current umask. The record has no trailing newline.
    pub(crate) fn write(path: &Path) -> Result<Self, StartupError> {
        Self::write_pid(path, process::id())
            .map_err(|_| StartupError::errno("Error: Unable to write pid file."))
    }

    fn write_pid(path: &Path, pid: u32) -> io::Result<Self> {
        let mut file = fs::File::create(path)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::other("not a regular file"));
        }
        let guard = Self(path.to_owned());
        write!(file, "{pid}")?;
        Ok(guard)
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        // Mosquitto src/mosquitto.c: post_shutdown_cleanup ignores remove errors.
        let _ = fs::remove_file(&self.0);
    }
}

// Mosquitto src/mosquitto.c: main sends only READY=1, ignores send errors and
// passes unset_environment=0 to sd_notify. No STOPPING=1 is sent.
pub(crate) fn notify_ready() {
    #[cfg(unix)]
    if let Some(path) = env::var_os("NOTIFY_SOCKET") {
        let _ = notify_socket(&path);
    }
}

#[cfg(unix)]
fn notify_socket(path: &std::ffi::OsStr) -> io::Result<()> {
    use std::os::unix::net::UnixDatagram;

    let socket = UnixDatagram::unbound()?;
    #[cfg(target_os = "linux")]
    if let Some(name) = path.as_encoded_bytes().strip_prefix(b"@") {
        use std::os::linux::net::SocketAddrExt as _;
        use std::os::unix::net::SocketAddr;

        if name.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NOTIFY_SOCKET has no abstract name",
            ));
        }

        return socket
            .send_to_addr(b"READY=1", &SocketAddr::from_abstract_name(name)?)
            .map(|_| ());
    }
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NOTIFY_SOCKET is not an absolute path",
        ));
    }
    socket.send_to(b"READY=1", path).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_record_is_decimal_without_newline_and_removed_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broker.pid");
        fs::write(&path, b"old content\n").unwrap();
        let guard = PidFile::write_pid(&path, 1234).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"1234");
        drop(guard);
        assert!(!path.exists());
        assert_eq!(
            PidFile::write(dir.path()).err().unwrap().code,
            ExitCode::from(14)
        );
    }

    #[cfg(unix)]
    #[test]
    fn umask_and_docker_ids_use_strtol_rules() {
        use std::ffi::OsStr;

        assert_eq!(parse_umask(OsStr::new("\t+0077")).unwrap(), 0o77);
        assert!(
            parse_umask(OsStr::new("01777"))
                .unwrap_err()
                .message
                .contains("out of range")
        );
        assert!(
            parse_umask(OsStr::new("077 "))
                .unwrap_err()
                .message
                .contains("not a valid octal")
        );
        assert_eq!(check_id(OsStr::new("\x0b+123"), "PUID").unwrap(), 123);
        assert!(
            check_id(OsStr::new("-1"), "PGID")
                .unwrap_err()
                .message
                .contains("must not be negative")
        );
        assert!(
            check_id(OsStr::new("2147483648"), "PUID")
                .unwrap_err()
                .message
                .contains("must not be less than")
        );
    }

    #[cfg(unix)]
    fn read_ready(socket: &std::os::unix::net::UnixDatagram) {
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut bytes = [0; 32];
        let len = socket.recv(&mut bytes).unwrap();
        assert_eq!(&bytes[..len], b"READY=1");
    }

    #[cfg(unix)]
    #[test]
    fn notify_writes_the_exact_datagram_to_a_filesystem_socket() {
        use std::os::unix::net::UnixDatagram;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify.sock");
        let socket = UnixDatagram::bind(&path).unwrap();
        notify_socket(path.as_os_str()).unwrap();
        read_ready(&socket);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn notify_writes_the_exact_datagram_to_an_abstract_socket() {
        use std::{
            ffi::OsStr,
            os::{
                linux::net::SocketAddrExt as _,
                unix::net::{SocketAddr, UnixDatagram},
            },
        };

        // A NUL after the namespace marker is part of the abstract socket name.
        let name = format!("mqextended-notify-{}\0test", process::id());
        let socket =
            UnixDatagram::bind_addr(&SocketAddr::from_abstract_name(name.as_bytes()).unwrap())
                .unwrap();
        // An environment variable cannot carry a NUL, but the sender handles the full
        // address byte sequence without treating it as a pathname.
        notify_socket(OsStr::new(&format!("@{name}"))).unwrap();
        read_ready(&socket);
    }
}
