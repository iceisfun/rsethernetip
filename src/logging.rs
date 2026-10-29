//! Structured logging interface for the crate's components.
//!
//! Port of Go `logging/`. Provides the [`Logger`] trait that all protocol
//! modules accept, a [`DefaultLogger`] that writes timestamped messages to a
//! `std::io::Write`, and a [`NopLogger`] that discards output.
//!
//! Logging is an implementation detail of this library and not part of any
//! ODVA/CIP specification.
//!
//! Deviation from Go: there is no `context.Context` parameter (Go ignores it
//! in every implementation here), and printf-style format strings become
//! `format_args!(...)` (`logger.info(format_args!("hello {}", 42))`).

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};
use std::io::Write;
use std::sync::{Arc, Mutex};

// Implementation detail (not spec): logging severity levels.
/// A logging level. Ordered from most verbose ([`Level::Trace`]) to
/// [`Level::None`], which disables all logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Level {
    /// The most verbose level (protocol-level byte tracing).
    Trace = 0,
    /// Debug messages.
    Debug = 1,
    /// General information.
    Info = 2,
    /// Warnings.
    Warn = 3,
    /// Errors.
    Error = 4,
    /// Disables all logging.
    None = 5,
}

impl Level {
    // Implementation detail (not spec): Go's `Level(99).String()` is
    // "UNKNOWN"; in Rust an out-of-range level cannot exist, so this maps
    // raw integers instead.
    /// Converts a raw integer to a level; out-of-range values give `None`
    /// (the Option, not the variant).
    pub fn from_i32(v: i32) -> Option<Level> {
        match v {
            0 => Some(Level::Trace),
            1 => Some(Level::Debug),
            2 => Some(Level::Info),
            3 => Some(Level::Warn),
            4 => Some(Level::Error),
            5 => Some(Level::None),
            _ => Option::None,
        }
    }

    // Implementation detail (not spec).
    /// Returns the upper-case name of the level (e.g. `"WARN"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Trace => "TRACE",
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
            Level::None => "NONE",
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// Implementation detail (not spec): structured fields attached to log lines.
/// Structured key/value fields (sorted by key for deterministic output).
pub type Fields = BTreeMap<String, String>;

// Implementation detail (not spec): the common logging interface.
/// Common logging interface for all components. Implementations must be safe
/// for concurrent use.
pub trait Logger: Send + Sync {
    /// Logs at the most verbose level (protocol byte tracing).
    fn trace(&self, args: fmt::Arguments<'_>);
    /// Logs a message useful during development and troubleshooting.
    fn debug(&self, args: fmt::Arguments<'_>);
    /// Logs general operational information such as connection events.
    fn info(&self, args: fmt::Arguments<'_>);
    /// Logs a potential problem that does not prevent normal operation.
    fn warn(&self, args: fmt::Arguments<'_>);
    /// Logs a failure.
    fn error(&self, args: fmt::Arguments<'_>);
    /// Returns a new logger that includes `fields` in every entry.
    fn with_fields(&self, fields: &Fields) -> Arc<dyn Logger>;
    /// Returns the current minimum log level.
    fn level(&self) -> Level;
    /// Changes the minimum log level at runtime.
    fn set_level(&self, level: Level);
    /// Rust stand-in for Go's `logger.(HexdumpLogger)` type assertion:
    /// returns `Some` if this logger also supports hex dumps.
    fn as_hexdump(&self) -> Option<&dyn HexdumpLogger> {
        None
    }
}

// Implementation detail (not spec): optional hex-dump extension.
/// Optional extension of [`Logger`] for wire-level hex dumps.
pub trait HexdumpLogger {
    /// Outputs a formatted hex dump of `data`, gated on the TRACE level.
    fn hexdump(&self, data: &[u8]);
}

// Implementation detail (not spec): discarding logger.
/// A [`Logger`] that silently discards all messages.
#[derive(Debug, Default, Clone, Copy)]
pub struct NopLogger;

impl NopLogger {
    /// Creates a new `NopLogger`.
    pub fn new() -> NopLogger {
        NopLogger
    }
}

impl Logger for NopLogger {
    fn trace(&self, _: fmt::Arguments<'_>) {}
    fn debug(&self, _: fmt::Arguments<'_>) {}
    fn info(&self, _: fmt::Arguments<'_>) {}
    fn warn(&self, _: fmt::Arguments<'_>) {}
    fn error(&self, _: fmt::Arguments<'_>) {}
    // Go returns the receiver unchanged since no fields are recorded.
    fn with_fields(&self, _: &Fields) -> Arc<dyn Logger> {
        Arc::new(NopLogger)
    }
    // Always `Level::None`.
    fn level(&self) -> Level {
        Level::None
    }
    fn set_level(&self, _: Level) {}
}

// Implementation detail (not spec): shared output sink so that child loggers
// created by `with_fields` serialise writes with their parent.
type Sink = Arc<Mutex<SinkInner>>;

struct SinkInner {
    writer: Box<dyn Write + Send>,
    is_stderr: bool,
}

// Implementation detail (not spec): default timestamped logger.
/// A structured [`Logger`] writing timestamped, level-prefixed lines to a
/// writer. Also implements [`HexdumpLogger`]. Defaults: `Level::Info`,
/// stdout.
pub struct DefaultLogger {
    level: Mutex<Level>,
    sink: Sink,
    fields: Fields,
}

// Implementation detail (not spec): functional options -> builder.
/// Builder for [`DefaultLogger`] (Go functional options `WithLevel`,
/// `WithWriter`, `WithLogFields`).
pub struct DefaultLoggerBuilder {
    level: Level,
    writer: Box<dyn Write + Send>,
    is_stderr: bool,
    fields: Fields,
}

impl Default for DefaultLoggerBuilder {
    fn default() -> Self {
        DefaultLoggerBuilder {
            level: Level::Info,
            writer: Box::new(std::io::stdout()),
            is_stderr: false,
            fields: Fields::new(),
        }
    }
}

impl DefaultLoggerBuilder {
    /// Sets the log level (Go `WithLevel`).
    pub fn level(mut self, level: Level) -> Self {
        self.level = level;
        self
    }
    /// Sets the output writer (Go `WithWriter`).
    pub fn writer<W: Write + Send + 'static>(mut self, w: W) -> Self {
        self.writer = Box::new(w);
        self.is_stderr = false;
        self
    }
    /// Writes to stderr.
    pub fn stderr(mut self) -> Self {
        self.writer = Box::new(std::io::stderr());
        self.is_stderr = true;
        self
    }
    /// Merges fields into the logger (Go `WithLogFields`).
    pub fn fields(mut self, fields: &Fields) -> Self {
        for (k, v) in fields {
            self.fields.insert(k.clone(), v.clone());
        }
        self
    }
    /// Adds a single field.
    pub fn field(mut self, k: impl Into<String>, v: impl fmt::Display) -> Self {
        self.fields.insert(k.into(), v.to_string());
        self
    }
    /// Builds the logger (Go `NewDefaultLogger`).
    pub fn build(self) -> DefaultLogger {
        DefaultLogger {
            level: Mutex::new(self.level),
            sink: Arc::new(Mutex::new(SinkInner { writer: self.writer, is_stderr: self.is_stderr })),
            fields: self.fields,
        }
    }
}

impl DefaultLogger {
    /// Creates a logger with defaults (`Level::Info`, stdout).
    pub fn new() -> DefaultLogger {
        DefaultLoggerBuilder::default().build()
    }

    /// Starts a builder (Go `NewDefaultLogger(options...)`).
    pub fn builder() -> DefaultLoggerBuilder {
        DefaultLoggerBuilder::default()
    }

    fn lvl(&self) -> Level {
        *self.level.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn log(&self, name: &str, args: fmt::Arguments<'_>) {
        let mut b = String::new();
        let _ = write!(b, "[{}] {}: {}", rfc3339_now(), name, args);
        self.write_fields(&mut b);
        if !b.ends_with('\n') {
            b.push('\n');
        }
        let mut s = self.sink.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(e) = s.writer.write_all(b.as_bytes())
            && !s.is_stderr {
                eprintln!("ERROR: Failed to write log entry: {e}");
            }
    }

    // Go formats fields as key="value" (%q) in map order (random); we sort.
    fn write_fields(&self, b: &mut String) {
        if self.fields.is_empty() {
            return;
        }
        b.push(' ');
        let parts: Vec<String> = self.fields.iter().map(|(k, v)| format!("{k}={v:?}")).collect();
        b.push_str(&parts.join(" "));
    }
}

impl Default for DefaultLogger {
    fn default() -> Self {
        DefaultLogger::new()
    }
}

macro_rules! level_fn {
    ($name:ident, $lvl:expr, $label:expr) => {
        fn $name(&self, args: fmt::Arguments<'_>) {
            if self.lvl() <= $lvl {
                self.log($label, args);
            }
        }
    };
}

impl Logger for DefaultLogger {
    level_fn!(trace, Level::Trace, "TRACE");
    level_fn!(debug, Level::Debug, "DEBUG");
    level_fn!(info, Level::Info, "INFO");
    level_fn!(warn, Level::Warn, "WARN");
    level_fn!(error, Level::Error, "ERROR");

    // Child shares the writer and merges parent + new fields.
    fn with_fields(&self, fields: &Fields) -> Arc<dyn Logger> {
        let mut merged = self.fields.clone();
        for (k, v) in fields {
            merged.insert(k.clone(), v.clone());
        }
        Arc::new(DefaultLogger { level: Mutex::new(self.lvl()), sink: self.sink.clone(), fields: merged })
    }
    fn level(&self) -> Level {
        self.lvl()
    }
    fn set_level(&self, level: Level) {
        *self.level.lock().unwrap_or_else(|e| e.into_inner()) = level;
    }
    fn as_hexdump(&self) -> Option<&dyn HexdumpLogger> {
        Some(self)
    }
}

impl HexdumpLogger for DefaultLogger {
    fn hexdump(&self, data: &[u8]) {
        if self.lvl() > Level::Trace {
            return;
        }
        let mut b = String::new();
        let _ = writeln!(b, "[{}] TRACE: HEXDUMP", rfc3339_now());
        b.push_str("offset   00 01 02 03 04 05 06 07 | 08 09 0a 0b 0c 0d 0e 0f\n");
        for (row, chunk) in data.chunks(16).enumerate() {
            let _ = write!(b, "{:08x}", row * 16);
            for j in 0..16 {
                if j == 8 {
                    b.push_str(" |");
                }
                b.push(' ');
                match chunk.get(j) {
                    Some(byte) => {
                        let _ = write!(b, "{byte:02x}");
                    }
                    None => b.push_str("  "),
                }
            }
            b.push('\n');
        }
        self.write_fields(&mut b);
        let mut s = self.sink.lock().unwrap_or_else(|e| e.into_inner());
        let _ = s.writer.write_all(b.as_bytes());
    }
}

// Implementation detail (not spec): std has no date formatting, so format
// the current UTC time as RFC 3339 (Go uses local time; we always use "Z").
fn rfc3339_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    rfc3339(secs)
}

// Civil-from-days algorithm (H. Hinnant), UTC.
fn rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test helper: writer whose contents can be inspected (Go bytes.Buffer).
    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl Buf {
        fn string(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    #[test]
    fn default_logger_levels() {
        let buf = Buf::default();
        let l = DefaultLogger::builder().level(Level::Warn).writer(buf.clone()).build();
        l.debug(format_args!("should not appear"));
        l.info(format_args!("should not appear"));
        l.warn(format_args!("warning message"));
        l.error(format_args!("error message"));
        let out = buf.string();
        assert!(!out.contains("DEBUG"), "debug message should not appear at warn level");
        assert!(!out.contains("INFO"), "info message should not appear at warn level");
        assert!(out.contains("WARN"));
        assert!(out.contains("ERROR"));
    }

    #[test]
    fn default_logger_formatting() {
        let buf = Buf::default();
        let l = DefaultLogger::builder().level(Level::Trace).writer(buf.clone()).build();
        l.info(format_args!("hello {} {}", "world", 42));
        let out = buf.string();
        assert!(out.contains("hello world 42"), "got: {out}");
        assert!(out.contains("INFO"), "got: {out}");
    }

    #[test]
    fn default_logger_with_fields() {
        let buf = Buf::default();
        let l = DefaultLogger::builder().level(Level::Info).writer(buf.clone()).build();
        let mut f = Fields::new();
        f.insert("component".into(), "transport".into());
        let child = l.with_fields(&f);
        child.info(format_args!("connected"));
        let out = buf.string();
        assert!(out.contains("component="), "got: {out}");
        assert!(out.contains("transport"), "got: {out}");
    }

    #[test]
    fn default_logger_set_level() {
        let l = DefaultLogger::builder().level(Level::Info).build();
        assert_eq!(l.level(), Level::Info);
        l.set_level(Level::Error);
        assert_eq!(l.level(), Level::Error);
    }

    #[test]
    fn nop_logger_implements_interface() {
        let l: Arc<dyn Logger> = Arc::new(NopLogger::new());
        l.trace(format_args!("trace"));
        l.debug(format_args!("debug"));
        l.info(format_args!("info"));
        l.warn(format_args!("warn"));
        l.error(format_args!("error"));
        let mut f = Fields::new();
        f.insert("k".into(), "v".into());
        l.with_fields(&f);
        assert_eq!(l.level(), Level::None);
    }

    #[test]
    fn level_string() {
        let tests = [
            (0, "TRACE"),
            (1, "DEBUG"),
            (2, "INFO"),
            (3, "WARN"),
            (4, "ERROR"),
            (5, "NONE"),
            (99, "UNKNOWN"),
        ];
        for (n, want) in tests {
            let got = Level::from_i32(n).map(|l| l.to_string()).unwrap_or_else(|| "UNKNOWN".into());
            assert_eq!(got, want, "Level({n})");
        }
    }

    #[test]
    fn default_logger_hexdump() {
        let buf = Buf::default();
        let l = DefaultLogger::builder().level(Level::Trace).writer(buf.clone()).build();
        let data = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        l.as_hexdump().expect("hexdump supported").hexdump(&data);
        let out = buf.string();
        assert!(out.contains("HEXDUMP"));
        assert!(out.contains("00 01 02 03"), "got: {out}");
    }

    #[test]
    fn rfc3339_known() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_709_210_096), "2024-02-29T12:34:56Z");
    }
}
