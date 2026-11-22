use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{self, Write},
    sync::Mutex,
};

use chrono::{
    Local, Utc,
    format::{Item, StrftimeItems},
};
use tracing::{Event, Level, Metadata, Subscriber};
use tracing_subscriber::{
    Layer as _, Registry,
    filter::filter_fn,
    fmt::{FmtContext, FormatEvent, FormatFields, MakeWriter, format::Writer},
    layer::SubscriberExt as _,
    registry::LookupSpan,
};

use crate::{LogConfig, LogDestination, LogType, ServerError};

/// Installs tracing for stderr/stdout/file. Syslog, DLT and `$SYS` are not emitted.
pub fn init_logging(config: &LogConfig) -> Result<(), ServerError> {
    let mut dest = Destinations::default();
    for destination in &config.destinations {
        match destination {
            LogDestination::Stderr => dest.stderr = true,
            LogDestination::Stdout => dest.stdout = true,
            LogDestination::File(path) => {
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|source| ServerError::File {
                        operation: "Unable to open log_dest file",
                        path: path.clone(),
                        source,
                    })?;
                dest.file = Some(Mutex::new(file));
            }
            LogDestination::Syslog | LogDestination::Dlt | LogDestination::Topic => (),
        }
    }
    let time = if config.timestamp {
        config
            .timestamp_format
            .as_deref()
            .map_or(Timestamp::UnixSeconds, |format| {
                StrftimeItems::new(format)
                    .parse_to_owned()
                    .map_or(Timestamp::Invalid, Timestamp::Local)
            })
    } else {
        Timestamp::Disabled
    };
    let enabled = dest.stderr || dest.stdout || dest.file.is_some();
    let types = config.types.clone();
    let layer = tracing_subscriber::fmt::layer()
        .event_format(LogFormat(time))
        .with_writer(dest)
        .with_ansi(false)
        .with_filter(filter_fn(move |metadata| {
            enabled && types.contains(&log_kind(metadata))
        }));
    tracing::subscriber::set_global_default(Registry::default().with(layer))
        .map_err(ServerError::Logging)
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

struct LogFormat(Timestamp);

enum Timestamp {
    Disabled,
    UnixSeconds,
    Local(Vec<Item<'static>>),
    Invalid,
}

impl<S, N> FormatEvent<S, N> for LogFormat
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        context: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        // Mosquitto src/logging.c: log__vprintf uses epoch seconds or local strftime.
        match &self.0 {
            Timestamp::Disabled => (),
            Timestamp::UnixSeconds => write!(writer, "{}: ", Utc::now().timestamp())?,
            Timestamp::Local(items) => {
                write!(writer, "{}: ", Local::now().format_with_items(items.iter()))?
            }
            Timestamp::Invalid => writer.write_str("Time error: ")?,
        }
        context
            .field_format()
            .format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

#[derive(Default)]
struct Destinations {
    stderr: bool,
    stdout: bool,
    file: Option<Mutex<File>>,
}

struct DestinationWriter<'a>(&'a Destinations);

impl<'a> MakeWriter<'a> for Destinations {
    type Writer = DestinationWriter<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        DestinationWriter(self)
    }
}

impl Write for DestinationWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut error = None;
        if self.0.stderr
            && let Err(err) = io::stderr().lock().write_all(buf)
        {
            error = Some(err);
        }
        if self.0.stdout
            && let Err(err) = io::stdout().lock().write_all(buf)
        {
            error.get_or_insert(err);
        }
        if let Some(file) = &self.0.file {
            let result = file
                .lock()
                .map_err(|_| io::Error::other("log file lock poisoned"))
                .and_then(|mut file| file.write_all(buf));
            if let Err(err) = result {
                error.get_or_insert(err);
            }
        }
        error.map_or(Ok(buf.len()), Err)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::stdout().flush()
    }
}
