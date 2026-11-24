//! go-auth's logger: logrus with `TextFormatter{FullTimestamp: true}`
//! (`go-auth.go: AuthPluginInit`).

use std::{
    fmt::{self, Write as _},
    io::{IsTerminal, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
};

/// `logrus.Level`. A lower value is more severe; an entry is written when its
/// level is at most the logger's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Level {
    Panic = 0,
    Fatal = 1,
    Error = 2,
    Warn = 3,
    Info = 4,
    Debug = 5,
}

impl Level {
    // logrus.go: Level.String
    fn name(self) -> &'static str {
        match self {
            Self::Panic => "panic",
            Self::Fatal => "fatal",
            Self::Error => "error",
            Self::Warn => "warning",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Panic,
            1 => Self::Fatal,
            2 => Self::Error,
            3 => Self::Warn,
            4 => Self::Info,
            _ => Self::Debug,
        }
    }
}

/// The plugin's logger. Clones share the level and the destination, as
/// go-auth's back-ends share the global logrus logger.
#[derive(Clone)]
pub(crate) struct Log(Arc<Inner>);

struct Inner {
    level: AtomicU8,
    output: Mutex<Output>,
}

struct Output {
    writer: Box<dyn Write + Send>,
    terminal: bool,
    colored: Option<bool>,
}

impl fmt::Debug for Log {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Log").field("level", &self.level()).finish()
    }
}

impl Log {
    pub(crate) fn new(level: Level, out: Box<dyn Write + Send>) -> Self {
        Self(Arc::new(Inner {
            level: AtomicU8::new(level as u8),
            output: Mutex::new(Output {
                writer: out,
                terminal: false,
                colored: None,
            }),
        }))
    }

    /// logrus's initial state: info level on stderr.
    pub(crate) fn stderr() -> Self {
        let stderr = std::io::stderr();
        let terminal = stderr.is_terminal();
        let log = Self::new(Level::Info, Box::new(stderr));
        log.0
            .output
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .terminal = terminal;
        log
    }

    pub(crate) fn level(&self) -> Level {
        Level::from_u8(self.0.level.load(Ordering::Relaxed))
    }

    /// `log.SetLevel`. Back-end constructors call it with the configured level.
    pub(crate) fn set_level(&self, level: Level) {
        self.0.level.store(level as u8, Ordering::Relaxed);
    }

    /// `log.SetOutput`.
    pub(crate) fn set_output(&self, writer: Box<dyn Write + Send>, terminal: bool) {
        let mut output = self.0.output.lock().unwrap_or_else(|e| e.into_inner());
        output.writer = writer;
        output.terminal = terminal;
    }

    pub(crate) fn enabled(&self, level: Level) -> bool {
        level <= self.level()
    }

    /// Writes a logrus text entry if `level` is enabled.
    pub(crate) fn log(&self, level: Level, message: fmt::Arguments<'_>) {
        if !self.enabled(level) {
            return;
        }
        let time = chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let mut line = String::new();
        let message = message.to_string();
        let mut output = self.0.output.lock().unwrap_or_else(|e| e.into_inner());
        // text_formatter.go: init caches terminal detection at the first
        // entry, even when SetOutput subsequently changes the destination.
        let terminal = output.terminal && !cfg!(windows);
        if *output.colored.get_or_insert(terminal) {
            let (color, name) = match level {
                Level::Panic => (31, "PANI"),
                Level::Fatal => (31, "FATA"),
                Level::Error => (31, "ERRO"),
                Level::Warn => (33, "WARN"),
                Level::Info => (36, "INFO"),
                Level::Debug => (37, "DEBU"),
            };
            let message = message.strip_suffix('\n').unwrap_or(&message);
            let _ = write!(line, "\x1b[{color}m{name}\x1b[0m[{time}] {message:<44} ");
        } else {
            line.push_str("time=");
            append_value(&mut line, &time);
            line.push_str(" level=");
            line.push_str(level.name());
            if !message.is_empty() {
                line.push_str(" msg=");
                append_value(&mut line, &message);
            }
        }
        line.push('\n');
        let _ = output.writer.write_all(line.as_bytes());
        let _ = output.writer.flush();
    }

    pub(crate) fn debug(&self, message: fmt::Arguments<'_>) {
        self.log(Level::Debug, message);
    }

    pub(crate) fn info(&self, message: fmt::Arguments<'_>) {
        self.log(Level::Info, message);
    }

    pub(crate) fn warn(&self, message: fmt::Arguments<'_>) {
        self.log(Level::Warn, message);
    }

    pub(crate) fn error(&self, message: fmt::Arguments<'_>) {
        self.log(Level::Error, message);
    }
}

// text_formatter.go: needsQuoting and appendValue (`fmt.Sprintf("%q", …)`).
fn append_value(line: &mut String, value: &str) {
    let plain = value.chars().all(|ch| {
        ch.is_ascii_alphanumeric() || matches!(ch, '-' | '.' | '_' | '/' | '@' | '^' | '+')
    });
    if plain {
        line.push_str(value);
        return;
    }
    line.push('"');
    for ch in value.chars() {
        match ch {
            '"' => line.push_str("\\\""),
            '\\' => line.push_str("\\\\"),
            '\x07' => line.push_str("\\a"),
            '\x08' => line.push_str("\\b"),
            '\x0c' => line.push_str("\\f"),
            '\n' => line.push_str("\\n"),
            '\r' => line.push_str("\\r"),
            '\t' => line.push_str("\\t"),
            '\x0b' => line.push_str("\\v"),
            ch if (ch as u32) < 0x20 || ch == '\x7f' => {
                let _ = write!(line, "\\x{:02x}", ch as u32);
            }
            ch if ch.is_control() => {
                if (ch as u32) < 0x10000 {
                    let _ = write!(line, "\\u{:04x}", ch as u32);
                } else {
                    let _ = write!(line, "\\U{:08x}", ch as u32);
                }
            }
            ch => line.push(ch),
        }
    }
    line.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn formats_like_logrus_text() {
        let buffer = Buffer::default();
        let log = Log::new(Level::Info, Box::new(buffer.clone()));
        log.info(format_args!("Backend registered: Files"));
        log.info(format_args!("redisCache"));
        log.debug(format_args!("hidden"));
        log.warn(format_args!("say \"hi\"\n"));
        let text = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        let lines: Vec<_> = text
            .lines()
            .map(|line| line.split_once(' ').unwrap().1)
            .collect();
        assert_eq!(
            lines,
            [
                "level=info msg=\"Backend registered: Files\"",
                "level=info msg=redisCache",
                "level=warning msg=\"say \\\"hi\\\"\\n\"",
            ]
        );
    }
}
