use std::{
    fmt::{self, Write as _},
    fs::{self, File, OpenOptions},
    io::{self, Write as _},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU16, Ordering},
    },
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::net::UnixDatagram;

use chrono::{Local, NaiveDateTime, Utc, format::Item, format::StrftimeItems};
use tokio::sync::mpsc;
use tracing::{Event, Level, Metadata, Subscriber, subscriber::Interest};
use tracing_subscriber::{
    Registry,
    fmt::FormatFields as _,
    fmt::format::{DefaultFields, Writer},
    layer::SubscriberExt as _,
};

use crate::{LogConfig, LogDestination, LogType, ServerError};

/// Before log__init, Mosquitto src/logging.c uses stderr and the default
/// priorities, but still uses the configured timestamp settings.
pub fn startup_log(config: &LogConfig, message: fmt::Arguments<'_>) {
    let mut line = Timestamp::new(config).line();
    let _ = line.write_fmt(message);
    let _ = io::stderr().lock().write_all(line.terminated());
}

/// Install the broker's log subscriber and return the live settings and MQTT log stream.
pub fn init_logging(config: &LogConfig) -> Result<(Logging, LogTopics), ServerError> {
    let (sender, receiver) = mpsc::channel(1024);
    let logging = Logging {
        state: Arc::new(LogState {
            sinks: Mutex::new(Sinks::empty(Timestamp::Disabled)),
            enabled: AtomicU16::new(0),
        }),
        sender,
    };
    tracing::subscriber::set_global_default(Registry::default().with(logging.clone()))
        .map_err(ServerError::Logging)?;
    logging.reload(config);
    Ok((logging, LogTopics(receiver)))
}

#[derive(Clone)]
pub struct Logging {
    state: Arc<LogState>,
    sender: mpsc::Sender<(&'static str, Vec<u8>)>,
}

struct LogState {
    sinks: Mutex<Sinks>,
    enabled: AtomicU16,
}

impl Logging {
    /// Mosquitto src/signals.c: signal__flag_check closes and reopens the
    /// destinations on SIGHUP, even if the log file's configured path is unchanged.
    pub fn reload(&self, config: &LogConfig) {
        let mut sinks = self.state.sinks.lock().expect("log sinks poisoned");
        *sinks = Sinks::new(config);
        if let Some(path) = config.destinations.iter().find_map(|destination| {
            if let LogDestination::File(path) = destination {
                Some(path)
            } else {
                None
            }
        }) {
            sinks.open_file(path, config.file_max_size, &self.sender);
        }
        self.state
            .enabled
            .store(sinks.effective_types(), Ordering::Relaxed);
    }
}

impl Sinks {
    fn open_file(
        &mut self,
        path: &Path,
        max_size: u64,
        sender: &mpsc::Sender<(&'static str, Vec<u8>)>,
    ) {
        match open_log_file(path, false) {
            Ok((file, size)) => {
                #[cfg(unix)]
                file_warnings(&file, path, |message| {
                    self.log(LogType::Information, message, sender);
                });
                self.file = Some(LogFile {
                    file,
                    path: path.to_owned(),
                    max_size,
                    size,
                    retry_at: None,
                });
            }
            Err(_) => {
                // Mosquitto src/logging.c: log__init continues with only stderr errors.
                let timestamp = std::mem::replace(&mut self.timestamp, Timestamp::Disabled);
                *self = Sinks {
                    stderr: true,
                    types: log_bit(LogType::Error),
                    ..Sinks::empty(timestamp)
                };
                self.log(
                    LogType::Error,
                    format_args!(
                        "Error: Unable to open log file {} for writing.",
                        path.display()
                    ),
                    sender,
                );
            }
        }
    }
}

pub struct LogTopics(mpsc::Receiver<(&'static str, Vec<u8>)>);

impl LogTopics {
    pub async fn serve(mut self, broker: mqx_broker::Broker) {
        while let Some((topic, line)) = self.0.recv().await {
            if let Err(error) = broker.publish_log(topic, line).await {
                tracing::debug!(%error, "MQTT log topic could not be published");
            }
        }
    }
}

impl<S: Subscriber> tracing_subscriber::Layer<S> for Logging {
    fn register_callsite(&self, metadata: &'static Metadata<'static>) -> Interest {
        if metadata.is_span() {
            Interest::never()
        } else {
            // Event and `tracing::enabled!` hint callsites must see reloaded filters.
            Interest::sometimes()
        }
    }

    fn enabled(
        &self,
        metadata: &Metadata<'_>,
        _: tracing_subscriber::layer::Context<'_, S>,
    ) -> bool {
        !metadata.is_span()
            && self.state.enabled.load(Ordering::Relaxed) & log_bit(log_kind(metadata)) != 0
    }

    fn on_event(&self, event: &Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        let mut sinks = self.state.sinks.lock().expect("log sinks poisoned");
        let kind = log_kind(event.metadata());
        if sinks.enabled(kind) {
            let mut line = sinks.timestamp.line();
            if DefaultFields::new()
                .format_fields(Writer::new(&mut line), event)
                .is_ok()
            {
                sinks.write(kind, line, &self.sender);
            }
        }
    }
}

struct Sinks {
    timestamp: Timestamp,
    types: u16,
    stderr: bool,
    stdout: bool,
    topics: bool,
    file: Option<LogFile>,
    #[cfg(unix)]
    syslog: Option<Syslog>,
}

impl Sinks {
    fn empty(timestamp: Timestamp) -> Self {
        Self {
            timestamp,
            types: 0,
            stderr: false,
            stdout: false,
            topics: false,
            file: None,
            #[cfg(unix)]
            syslog: None,
        }
    }

    fn new(config: &LogConfig) -> Self {
        let mut sinks = Self::empty(Timestamp::new(config));
        sinks.types = config
            .types
            .iter()
            .fold(0, |mask, &kind| mask | log_bit(kind));
        for destination in &config.destinations {
            match destination {
                LogDestination::Stderr => sinks.stderr = true,
                LogDestination::Stdout => sinks.stdout = true,
                LogDestination::Topic => sinks.topics = true,
                #[cfg(unix)]
                LogDestination::Syslog => {
                    sinks.syslog = Some(Syslog {
                        facility: config.facility,
                        socket: None,
                    })
                }
                // Mosquitto src/conf.c parses dlt even without WITH_DLT; this
                // build has no DLT runtime, as in src/logging.c without WITH_DLT.
                _ => {}
            }
        }
        sinks
    }

    fn effective_types(&self) -> u16 {
        #[cfg(unix)]
        let syslog = self.syslog.is_some();
        #[cfg(not(unix))]
        let syslog = false;
        if self.stdout || self.stderr || self.file.is_some() || syslog {
            self.types
        } else if self.topics {
            self.types & !(log_bit(LogType::Debug) | log_bit(LogType::Internal))
        } else {
            0
        }
    }

    fn enabled(&self, kind: LogType) -> bool {
        self.effective_types() & log_bit(kind) != 0
    }

    fn log(
        &mut self,
        kind: LogType,
        message: fmt::Arguments<'_>,
        sender: &mpsc::Sender<(&'static str, Vec<u8>)>,
    ) {
        if self.enabled(kind) {
            let mut line = self.timestamp.line();
            let _ = line.write_fmt(message);
            self.write(kind, line, sender);
        }
    }

    fn write(
        &mut self,
        kind: LogType,
        mut line: Line<1000>,
        sender: &mpsc::Sender<(&'static str, Vec<u8>)>,
    ) {
        let terminated = line.terminated();
        self.write_remaining(kind, terminated, sender);
        if let Some(file) = &mut self.file
            && let Some(error) = file.write(terminated)
        {
            // Don't send rotation diagnostics back into the failing file sink.
            let mut warning = self.timestamp.line();
            let _ = write!(
                warning,
                "Warning: Unable to rotate log file {}: {error}",
                file.path.display()
            );
            self.write_remaining(LogType::Warning, warning.terminated(), sender);
        }
    }

    fn write_remaining(
        &mut self,
        kind: LogType,
        terminated: &[u8],
        sender: &mpsc::Sender<(&'static str, Vec<u8>)>,
    ) {
        if self.stdout {
            let _ = io::stdout().lock().write_all(terminated);
        }
        if self.stderr {
            let _ = io::stderr().lock().write_all(terminated);
        }
        let line = &terminated[..terminated.len() - 1];
        #[cfg(unix)]
        if let Some(syslog) = &mut self.syslog {
            syslog.write(kind, line);
        }
        if self.topics
            && let Some(topic) = topic(kind)
            && let Ok(permit) = sender.try_reserve()
        {
            permit.send((topic, line.to_vec()));
        }
    }
}

const fn log_bit(kind: LogType) -> u16 {
    1 << kind as u16
}

fn topic(kind: LogType) -> Option<&'static str> {
    // Mosquitto src/logging.c: log__vprintf excludes debug and internal.
    // Built-in websockets use the default severity, unlike libwebsockets.
    Some(match kind {
        LogType::Error => "$SYS/broker/log/E",
        LogType::Warning => "$SYS/broker/log/W",
        LogType::Information => "$SYS/broker/log/I",
        LogType::Notice => "$SYS/broker/log/N",
        LogType::Subscribe => "$SYS/broker/log/M/subscribe",
        LogType::Unsubscribe => "$SYS/broker/log/M/unsubscribe",
        LogType::Websockets => "$SYS/broker/log/E",
        LogType::Debug | LogType::Internal => return None,
    })
}

fn log_kind(metadata: &Metadata<'_>) -> LogType {
    match metadata.target() {
        "mqx::notice" => LogType::Notice,
        "mqx::subscribe" => LogType::Subscribe,
        "mqx::unsubscribe" => LogType::Unsubscribe,
        "mqx::websockets" => LogType::Websockets,
        _ => match *metadata.level() {
            Level::ERROR => LogType::Error,
            Level::WARN => LogType::Warning,
            Level::INFO => LogType::Information,
            Level::DEBUG => LogType::Debug,
            Level::TRACE => LogType::Internal,
        },
    }
}

enum Timestamp {
    Disabled,
    UnixSeconds,
    Local(Vec<Item<'static>>),
}

impl Timestamp {
    fn new(config: &LogConfig) -> Self {
        if !config.timestamp {
            return Self::Disabled;
        }
        config
            .timestamp_format
            .as_deref()
            .map_or(Self::UnixSeconds, |format| {
                Self::Local(
                    StrftimeItems::new_lenient(format)
                        .parse_to_owned()
                        .expect("lenient strftime parser"),
                )
            })
    }

    // Mosquitto src/logging.c: log__vprintf uses epoch seconds or local strftime.
    fn line(&self) -> Line<1000> {
        let mut line = Line::new();
        match self {
            Self::Disabled => return line,
            Self::UnixSeconds => {
                let _ = write!(line, "{}", Utc::now().timestamp());
            }
            Self::Local(items) => {
                let result = Local::now()
                    .format_with_items(items.iter())
                    .write_to(&mut line);
                if result.is_err() || line.len == 0 || line.truncated {
                    line.len = 0;
                    line.truncated = false;
                    let _ = line.write_str("Time error");
                }
            }
        }
        if line.len < 997 {
            let _ = line.write_str(": ");
        }
        line
    }
}

// Mosquitto src/logging.c: log__vprintf uses a 1000-byte buffer including its
// NUL; truncate bytes rather than characters and reserve the last byte for
// the newline in the stream destinations.
struct Line<const N: usize> {
    buffer: [u8; N],
    len: usize,
    truncated: bool,
    nul: bool,
}

impl<const N: usize> Line<N> {
    fn new() -> Self {
        Self {
            buffer: [0; N],
            len: 0,
            truncated: false,
            nul: false,
        }
    }

    fn bytes(&self) -> &[u8] {
        &self.buffer[..self.len]
    }

    fn terminated(&mut self) -> &[u8] {
        self.buffer[self.len] = b'\n';
        &self.buffer[..=self.len]
    }

    fn append(&mut self, bytes: &[u8]) {
        let len = bytes.len().min(N - 1 - self.len);
        self.buffer[self.len..self.len + len].copy_from_slice(&bytes[..len]);
        self.len += len;
        self.truncated |= len < bytes.len();
    }
}

impl<const N: usize> fmt::Write for Line<N> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if !self.nul {
            let bytes = value.as_bytes();
            if let Some(nul) = bytes.iter().position(|&b| b == 0) {
                self.append(&bytes[..nul]);
                self.nul = true;
            } else {
                self.append(bytes);
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
struct Syslog {
    facility: u8,
    socket: Option<UnixDatagram>,
}

#[cfg(unix)]
impl Syslog {
    fn write(&mut self, kind: LogType, line: &[u8]) {
        let packet = syslog_packet(self.facility, kind, Local::now(), std::process::id(), line);
        self.write_packet(Path::new("/dev/log"), packet.bytes());
    }

    // Mosquitto src/logging.c uses openlog("mosquitto", LOG_PID|LOG_CONS, ...)
    // and syslog(). Deliver one datagram per event without a NUL or newline.
    fn write_packet(&mut self, path: &Path, packet: &[u8]) {
        if let Some(socket) = &self.socket
            && socket.send(packet).is_ok()
        {
            return;
        }
        self.socket = UnixDatagram::unbound()
            .ok()
            .filter(|socket| socket.connect(path).is_ok() && socket.send(packet).is_ok());
    }
}

#[cfg(unix)]
fn syslog_packet(
    facility: u8,
    kind: LogType,
    time: chrono::DateTime<Local>,
    pid: u32,
    line: &[u8],
) -> Line<1100> {
    let priority = match kind {
        LogType::Error | LogType::Internal | LogType::Websockets => 3, // LOG_ERR
        LogType::Warning => 4,
        LogType::Notice | LogType::Subscribe | LogType::Unsubscribe => 5,
        LogType::Information => 6,
        LogType::Debug => 7,
    };
    let mut packet = Line::new();
    let pri = (u16::from(facility) << 3) | priority;
    let _ = write!(packet, "<{pri}>");
    let _ = time.format("%b %e %T").write_to(&mut packet);
    let _ = write!(packet, " mosquitto[{pid}]: ");
    packet.append(line);
    packet
}

const ROTATION_STAMP: &str = "%Y%m%dT%H%M%S.%9fZ";
const ROTATION_KEEP: usize = 4;
const ROTATION_RETRY: Duration = Duration::from_secs(60);

struct LogFile {
    file: File,
    path: PathBuf,
    max_size: u64,
    size: u64,
    retry_at: Option<Instant>,
}

impl LogFile {
    fn write(&mut self, line: &[u8]) -> Option<io::Error> {
        let written = self.file.write_all(line);
        if self.max_size == 0 {
            return None;
        }
        self.size = if written.is_ok() {
            self.size.saturating_add(line.len() as u64)
        } else {
            // A partial write may have crossed the threshold.
            self.max_size
        };
        if self.size < self.max_size || self.retry_at.is_some_and(|retry| Instant::now() < retry) {
            return None;
        }
        match self.rotate_if_full() {
            Ok(()) => {
                self.retry_at = None;
                None
            }
            Err(error) => {
                let warn = self.retry_at.is_none();
                self.retry_at = Some(Instant::now() + ROTATION_RETRY);
                warn.then_some(error)
            }
        }
    }

    fn rotate_if_full(&mut self) -> io::Result<()> {
        let opened = self.file.metadata()?;
        self.size = opened.len();
        // No fstat in the normal write path. A copytruncate can only make
        // the cached length an overestimate; check it before rotating.
        if self.size < self.max_size {
            return Ok(());
        }
        let active = fs::symlink_metadata(&self.path)?;
        if !active.is_file() || !same_log_file(&opened, &active) {
            return Err(io::Error::other(
                "the active log path no longer names the open file",
            ));
        }

        let mut archive = self.path.clone();
        archive
            .as_mut_os_string()
            .push(format!(".{}", Utc::now().format(ROTATION_STAMP)));
        move_log(&self.path, &archive)?;
        // main opens logs after drop_privileges. The replacement uses the
        // running identity and must never open an entry created by someone else.
        match open_log_file(&self.path, true) {
            Ok((file, size)) => {
                self.file = file;
                self.size = size;
            }
            Err(error) => {
                // Keep the old descriptor even if restoring its path fails.
                let _ = move_log(&archive, &self.path);
                return Err(error);
            }
        }
        prune_rotated_logs(&self.path)
    }
}

#[cfg(unix)]
fn same_log_file(opened: &fs::Metadata, active: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    (opened.dev(), opened.ino()) == (active.dev(), active.ino())
}

#[cfg(not(unix))]
fn same_log_file(opened: &fs::Metadata, active: &fs::Metadata) -> bool {
    opened.len() == active.len() && opened.created().ok() == active.created().ok()
}

fn move_log(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        use nix::{
            errno::Errno,
            fcntl::{AT_FDCWD, RenameFlags, renameat2},
        };

        match renameat2(AT_FDCWD, from, AT_FDCWD, to, RenameFlags::RENAME_NOREPLACE) {
            Err(Errno::EINVAL | Errno::ENOSYS | Errno::EOPNOTSUPP) => {}
            result => return result.map_err(io::Error::from),
        }
    }
    // Fallback where NOREPLACE isn't available. Never overwrite a same-stamp
    // archive (or, on rollback, a replacement for the active file).
    fs::hard_link(from, to)?;
    fs::remove_file(from).inspect_err(|_| {
        let _ = fs::remove_file(to);
    })
}

fn prune_rotated_logs(path: &Path) -> io::Result<()> {
    let directory = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let basename = path.file_name().expect("open regular file has a basename");
    let mut newest = Vec::with_capacity(ROTATION_KEEP);
    let mut failure = Ok(());
    for entry in directory.read_dir()? {
        let entry = entry?;
        let name = entry.file_name();
        if !is_rotated_log(basename.as_encoded_bytes(), name.as_encoded_bytes())
            || !entry.file_type()?.is_file()
        {
            continue;
        }
        if newest.len() < ROTATION_KEEP {
            newest.push(name);
            continue;
        }
        let oldest = newest
            .iter_mut()
            .min()
            .expect("retention keeps at least one log");
        let stale = if name > *oldest {
            std::mem::replace(oldest, name)
        } else {
            name
        };
        if let Err(error) = fs::remove_file(directory.join(stale))
            && error.kind() != io::ErrorKind::NotFound
            && failure.is_ok()
        {
            failure = Err(error);
        }
    }
    failure
}

fn is_rotated_log(basename: &[u8], name: &[u8]) -> bool {
    let Some(stamp) = name
        .strip_prefix(basename)
        .and_then(|suffix| suffix.strip_prefix(b"."))
    else {
        return false;
    };
    stamp.len() == 26
        && stamp[8] == b'T'
        && stamp[15] == b'.'
        && stamp[25] == b'Z'
        && stamp[..8]
            .iter()
            .chain(&stamp[9..15])
            .chain(&stamp[16..25])
            .all(u8::is_ascii_digit)
        && NaiveDateTime::parse_from_str(std::str::from_utf8(stamp).expect("ASCII"), ROTATION_STAMP)
            .is_ok()
}

fn open_log_file(path: &Path, create_only: bool) -> io::Result<(File, u64)> {
    let mut options = OpenOptions::new();
    options.append(true);
    #[cfg(unix)]
    let allow_symlinks = {
        use std::os::unix::fs::OpenOptionsExt as _;

        // libcommon/file_common.c: mosquitto_fopen restrict_read enables O_NOFOLLOW
        // and creates the file with 0600 (independent of UMASK_SET).
        let allow = !create_only && std::env::var_os("MOSQUITTO_UNSAFE_ALLOW_SYMLINKS").is_some();
        options.mode(0o600);
        if !allow {
            options.custom_flags(nix::libc::O_NOFOLLOW);
        }
        allow
    };
    #[cfg(not(unix))]
    let allow_symlinks = true;

    let (file, metadata) = match options.create_new(true).open(path) {
        Ok(file) => {
            let metadata = file.metadata()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;

                if metadata.permissions().mode() & 0o777 != 0o600 {
                    file.set_permissions(fs::Permissions::from_mode(0o600))?;
                }
            }
            (file, metadata)
        }
        Err(error) if !create_only && error.kind() == io::ErrorKind::AlreadyExists => {
            let file = options
                .create_new(false)
                .create(allow_symlinks)
                .open(path)?;
            let metadata = file.metadata()?;
            (file, metadata)
        }
        Err(error) => return Err(error),
    };
    if !metadata.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    Ok((file, metadata.len()))
}

#[cfg(unix)]
fn file_warnings(file: &File, path: &Path, mut log: impl FnMut(fmt::Arguments<'_>)) {
    use nix::unistd::{Group, User, getgid, getuid};
    use std::os::unix::fs::MetadataExt as _;

    let Ok(metadata) = file.metadata() else {
        return;
    };
    if metadata.mode() & 0o007 != 0 {
        log(format_args!(
            "Warning: File {} has world readable permissions. Future versions will refuse to load this file.\nTo fix this, use `chmod 0700 {}`.\n",
            path.display(),
            path.display()
        ));
    }
    let uid = getuid();
    if metadata.uid() != uid.as_raw()
        && let Ok(Some(owner)) = User::from_uid(uid)
    {
        log(format_args!(
            "Warning: File {} owner is not {}. Future versions will refuse to load this file.To fix this, use `chown {} {}`.\n",
            path.display(),
            owner.name,
            owner.name,
            path.display()
        ));
    }
    let gid = getgid();
    if metadata.gid() != gid.as_raw()
        && let Ok(Some(group)) = Group::from_gid(gid)
    {
        log(format_args!(
            "Warning: File {} group is not {}. Future versions will refuse to load this file.\n",
            path.display(),
            group.name
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_and_topic_payload_share_mosquittos_byte_limit() {
        let mut line = Timestamp::Disabled.line();
        let message = format!("{}é ignored", "a".repeat(998));
        line.write_str(&message).unwrap();
        assert_eq!(line.bytes().len(), 999);
        assert_eq!(line.bytes()[998], 0xc3);
        assert_eq!(&line.terminated()[998..], b"\xc3\n");
    }

    #[test]
    fn dlt_and_none_do_not_enable_stderr_or_topics_in_this_build() {
        for destinations in ["log_dest dlt\n", "log_dest stderr\nlog_dest none\n"] {
            let log = crate::ServerConfig::parse(destinations).unwrap().log;
            assert!(!Sinks::new(&log).enabled(LogType::Error));
        }
    }

    #[test]
    fn file_rotation_limit_defaults_to_64_mib_and_accepts_byte_counts() {
        assert_eq!(LogConfig::default().file_max_size, 64 * 1024 * 1024);
        for size in [0, 127, u64::MAX] {
            let log = crate::ServerConfig::parse(&format!("log_file_max_size {size}\n"))
                .unwrap()
                .log;
            assert_eq!(log.file_max_size, size);
        }
        assert!(crate::ServerConfig::parse("log_file_max_size -1\n").is_err());
    }

    fn file_sink(path: &Path, max_size: u64) -> LogFile {
        let (file, size) = open_log_file(path, false).unwrap();
        LogFile {
            file,
            path: path.to_owned(),
            max_size,
            size,
            retry_at: None,
        }
    }

    #[test]
    fn file_rotation_starts_at_the_threshold_and_keeps_the_newest_four() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broker.log");
        let unrelated = [
            "broker.log.1",
            "broker.log.1.gz",
            "broker.log-20000101",
            "broker.log.20000101T000001.000000000Z.gz",
            "broker.log.20001301T000001.000000000Z",
            "another.log.20000101T000001.000000000Z",
        ];
        for name in unrelated {
            fs::write(dir.path().join(name), b"unrelated").unwrap();
        }
        let old_archive = dir.path().join("broker.log.20000101T000001.000000000Z");
        fs::write(&old_archive, b"old archive").unwrap();
        let mut sink = file_sink(&path, 4);

        assert!(sink.write(b"a\n").is_none());
        assert_eq!(fs::read(&path).unwrap(), b"a\n");
        assert!(sink.write(b"b\n").is_none());
        assert!(
            fs::read(&path).unwrap().is_empty(),
            "rotate at exactly 4 bytes"
        );
        for line in [b"222\n", b"333\n", b"444\n", b"555\n", b"666\n"] {
            assert!(sink.write(line).is_none());
        }
        assert!(sink.write(b"z\n").is_none());
        assert_eq!(fs::read(&path).unwrap(), b"z\n");

        let mut archives: Vec<_> = dir
            .path()
            .read_dir()
            .unwrap()
            .map(|entry| entry.unwrap())
            .filter(|entry| is_rotated_log(b"broker.log", entry.file_name().as_encoded_bytes()))
            .map(|entry| entry.path())
            .collect();
        archives.sort_unstable();
        let contents: Vec<_> = archives
            .iter()
            .map(|path| fs::read(path).unwrap())
            .collect();
        assert_eq!(contents, [b"333\n", b"444\n", b"555\n", b"666\n"]);
        assert!(!old_archive.exists());
        for name in unrelated {
            assert_eq!(fs::read(dir.path().join(name)).unwrap(), b"unrelated");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let current = fs::metadata(&path).unwrap();
            assert_eq!(current.mode() & 0o777, 0o600);
            assert_eq!(current.uid(), nix::unistd::geteuid().as_raw());
        }
    }

    #[test]
    fn copytruncate_does_not_trigger_rotation_before_the_new_length_reaches_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broker.log");
        let mut sink = file_sink(&path, 4);
        assert!(sink.write(b"a\n").is_none());
        fs::copy(&path, dir.path().join("broker.log.1")).unwrap();
        File::options()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        assert!(sink.write(b"b\n").is_none());
        assert_eq!(fs::read(&path).unwrap(), b"b\n");
        assert!(sink.write(b"c\n").is_none());
        assert!(fs::read(&path).unwrap().is_empty());
        assert_eq!(fs::read(dir.path().join("broker.log.1")).unwrap(), b"a\n");
    }

    #[test]
    fn zero_file_rotation_limit_keeps_appending_to_an_existing_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broker.log");
        fs::write(&path, b"old\n").unwrap();
        let mut sink = file_sink(&path, 0);
        assert!(sink.write(b"new\n").is_none());
        assert_eq!(fs::read(&path).unwrap(), b"old\nnew\n");
        assert_eq!(dir.path().read_dir().unwrap().count(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn failed_log_rename_warns_once_to_other_destinations_and_keeps_appending() {
        let dir = tempfile::tempdir().unwrap();
        // The original basename fits NAME_MAX, but not with the appended timestamp.
        let path = dir.path().join("l".repeat(255));
        let config = crate::ServerConfig::parse("log_dest topic\nlog_timestamp false\n")
            .unwrap()
            .log;
        let mut sinks = Sinks::new(&config);
        let (sender, mut receiver) = mpsc::channel(8);
        sinks.open_file(&path, 2, &sender);
        for message in ["a", "b", "c"] {
            sinks.log(LogType::Notice, format_args!("{message}"), &sender);
        }
        assert_eq!(fs::read(&path).unwrap(), b"a\nb\nc\n");
        let warnings: Vec<_> = std::iter::from_fn(|| receiver.try_recv().ok())
            .filter_map(|(topic, line)| (topic == "$SYS/broker/log/W").then_some(line))
            .collect();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].starts_with(b"Warning: Unable to rotate log file"));
    }

    #[cfg(unix)]
    #[test]
    fn creating_the_new_log_never_follows_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broker.log");
        let target = dir.path().join("elsewhere");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert_eq!(
            open_log_file(&path, true).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert!(!target.exists());
    }

    #[cfg(unix)]
    #[test]
    fn file_rotation_retries_after_the_active_path_is_restored() {
        let dir = tempfile::tempdir().unwrap();
        let active = dir.path().join("broker.log");
        let external = dir.path().join("broker.log.1");
        let mut sink = file_sink(&active, 2);
        fs::rename(&active, &external).unwrap();
        fs::write(&active, b"external replacement").unwrap();

        assert!(sink.write(b"a\n").is_some());
        assert!(sink.write(b"b\n").is_none());
        assert_eq!(fs::read(&external).unwrap(), b"a\nb\n");
        assert_eq!(fs::read(&active).unwrap(), b"external replacement");

        fs::rename(&external, &active).unwrap();
        sink.retry_at = Some(Instant::now());
        assert!(sink.write(b"c\n").is_none());
        assert!(fs::read(&active).unwrap().is_empty());
        assert!(sink.retry_at.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn syslog_uses_facility_severity_pid_and_the_unterminated_broker_line() {
        use chrono::TimeZone as _;
        use std::time::Duration;

        let path = tempfile::tempdir().unwrap();
        let path = path.path().join("log.sock");
        let receiver = UnixDatagram::bind(&path).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let log = crate::ServerConfig::parse("log_facility 7\n").unwrap().log;
        let time = Local
            .with_ymd_and_hms(2026, 1, 2, 3, 4, 5)
            .single()
            .unwrap();
        let mut sink = Syslog {
            facility: log.facility,
            socket: None,
        };
        for (kind, pri) in [
            (LogType::Error, 187),
            (LogType::Warning, 188),
            (LogType::Notice, 189),
            (LogType::Subscribe, 189),
            (LogType::Unsubscribe, 189),
            (LogType::Information, 190),
            (LogType::Debug, 191),
        ] {
            let line = b"1767323045: broker log";
            let packet = syslog_packet(sink.facility, kind, time, 42, line);
            sink.write_packet(&path, packet.bytes());
            let mut received = [0; 80];
            let bytes = receiver.recv(&mut received).unwrap();
            let expected = format!("<{pri}>Jan  2 03:04:05 mosquitto[42]: 1767323045: broker log");
            assert_eq!(&received[..bytes], expected.as_bytes());
        }
    }
}
