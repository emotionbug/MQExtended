use std::{
    fmt::{self, Write as _},
    fs::{File, OpenOptions},
    io::{self, Write as _},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU16, Ordering},
    },
};

#[cfg(unix)]
use std::os::unix::net::UnixDatagram;

use chrono::{Local, Utc, format::Item, format::StrftimeItems};
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
            sinks.open_file(path, &self.sender);
        }
        self.state
            .enabled
            .store(sinks.effective_types(), Ordering::Relaxed);
    }
}

impl Sinks {
    fn open_file(&mut self, path: &Path, sender: &mpsc::Sender<(&'static str, Vec<u8>)>) {
        match open_log_file(path) {
            Ok(file) => {
                #[cfg(unix)]
                file_warnings(&file, path, |message| {
                    self.log(LogType::Information, message, sender);
                });
                self.file = Some(file);
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
    file: Option<File>,
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
        if self.stdout {
            let _ = io::stdout().lock().write_all(terminated);
        }
        if self.stderr {
            let _ = io::stderr().lock().write_all(terminated);
        }
        if let Some(file) = &mut self.file {
            let _ = file.write_all(terminated);
        }
        #[cfg(unix)]
        if let Some(syslog) = &mut self.syslog {
            syslog.write(kind, line.bytes());
        }
        if self.topics
            && let Some(topic) = topic(kind)
            && let Ok(permit) = sender.try_reserve()
        {
            permit.send((topic, line.bytes().to_vec()));
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

fn open_log_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.append(true);
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        // libcommon/file_common.c: mosquitto_fopen restrict_read enables O_NOFOLLOW
        // and creates the file with 0600 (independent of UMASK_SET).
        let allow_symlinks = std::env::var_os("MOSQUITTO_UNSAFE_ALLOW_SYMLINKS").is_some();
        if !allow_symlinks {
            options.custom_flags(nix::libc::O_NOFOLLOW);
        }
        match options.create_new(true).mode(0o600).open(path) {
            Ok(file) => {
                if file.metadata()?.permissions().mode() & 0o777 != 0o600 {
                    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
                }
                file
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => options
                .create_new(false)
                .create(allow_symlinks)
                .open(path)?,
            Err(error) => return Err(error),
        }
    };
    #[cfg(not(unix))]
    let file = options.create(true).open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    Ok(file)
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
