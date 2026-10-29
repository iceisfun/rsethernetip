//! Protocol-agnostic abstractions for communicating with industrial PLCs.
//!
//! Port of Go `plc/`. Provides the [`Plc`] trait for reading and writing data
//! points, plus a [`Value`] type carrying raw bytes with type and byte-order
//! metadata so callers can interpret responses without depending on a
//! specific protocol.
//!
//! This module is a library abstraction, not itself defined by a spec; the
//! per-type comments cite the spec where a variant mirrors a protocol type.
//!
//! Also defines [`Context`], the Rust replacement for Go's `context.Context`
//! (deadline + shared cancel flag), used across the crate.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

// Implementation detail (not spec): Go `context.Context` replacement.
/// Cancellation/deadline carrier replacing Go's `context.Context`.
///
/// Cloning shares the cancel flag: cancelling any clone cancels all.
/// [`Context::with_timeout`] derives a child that shares the parent's flag and
/// uses the earlier of the two deadlines.
#[derive(Debug, Clone, Default)]
pub struct Context {
    cancel: Arc<AtomicBool>,
    deadline: Option<Instant>,
}

impl Context {
    /// A context that is never cancelled and has no deadline
    /// (Go `context.Background()`).
    pub fn background() -> Context {
        Context::default()
    }

    /// Derives a context with a deadline `timeout` from now (or the parent's
    /// deadline if earlier). Shares the cancel flag.
    pub fn with_timeout(&self, timeout: Duration) -> Context {
        self.with_deadline(Instant::now() + timeout)
    }

    /// Derives a context with an absolute deadline (earlier wins).
    pub fn with_deadline(&self, deadline: Instant) -> Context {
        let d = match self.deadline {
            Some(p) if p < deadline => p,
            _ => deadline,
        };
        Context { cancel: self.cancel.clone(), deadline: Some(d) }
    }

    /// A fresh cancellable context with no deadline.
    pub fn new_cancellable() -> Context {
        Context::default()
    }

    /// Cancels this context and every clone/child sharing its flag.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }

    /// Returns true if cancelled explicitly.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }

    /// Returns true if the deadline has passed.
    pub fn is_expired(&self) -> bool {
        self.deadline.is_some_and(|d| Instant::now() >= d)
    }

    /// Returns true if cancelled or past the deadline (Go `ctx.Done()`).
    pub fn is_done(&self) -> bool {
        self.is_cancelled() || self.is_expired()
    }

    /// Returns the deadline if any.
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Time left until the deadline (`None` = unbounded; zero if passed).
    pub fn remaining(&self) -> Option<Duration> {
        self.deadline.map(|d| d.saturating_duration_since(Instant::now()))
    }

    /// Like Go's `ctx.Err()`: `None` while live, else the reason.
    pub fn err(&self) -> Option<Error> {
        if self.is_cancelled() {
            Some(Error::Cancelled)
        } else if self.is_expired() {
            Some(Error::DeadlineExceeded)
        } else {
            None
        }
    }
}

// Implementation detail (not spec): error type for this layer.
/// Errors from the `plc` layer. Messages match the Go `plc: ...` strings.
#[derive(Debug)]
pub enum Error {
    /// Multi-byte integer requested but the `Value` has no byte order.
    ByteOrderRequired(usize),
    /// Float requested but the `Value` has no byte order.
    ByteOrderRequiredFloat(&'static str),
    /// Raw length is not 1/2/4/8 for signed integer decoding.
    CannotInterpretInt(usize),
    /// Raw length is not 1/2/4/8 for unsigned integer decoding.
    CannotInterpretUint(usize),
    /// Raw length does not match the float width (type name, expected, got).
    WrongSize(&'static str, usize, usize),
    /// Context cancelled (Go `context.Canceled`).
    Cancelled,
    /// Context deadline passed (Go `context.DeadlineExceeded`).
    DeadlineExceeded,
    /// Not connected.
    NotConnected,
    /// Any protocol-specific failure from an implementation.
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl Error {
    /// Wraps a protocol-specific error.
    pub fn other<E: std::error::Error + Send + Sync + 'static>(e: E) -> Error {
        Error::Other(Box::new(e))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ByteOrderRequired(n) => write!(f, "plc: byte order required for {n}-byte value"),
            Error::ByteOrderRequiredFloat(t) => write!(f, "plc: byte order required for {t}"),
            Error::CannotInterpretInt(n) => write!(f, "plc: cannot interpret {n} bytes as integer"),
            Error::CannotInterpretUint(n) => write!(f, "plc: cannot interpret {n} bytes as unsigned integer"),
            Error::WrongSize(t, want, got) => write!(f, "plc: expected {want} bytes for {t}, got {got}"),
            Error::Cancelled => f.write_str("context canceled"),
            Error::DeadlineExceeded => f.write_str("context deadline exceeded"),
            Error::NotConnected => f.write_str("plc: not connected"),
            Error::Other(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Other(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

/// Result alias for the `plc` layer.
pub type Result<T> = std::result::Result<T, Error>;

// Ref: CIP Vol. 1, Appendix C (Data Management / elementary data types,
// section unverified) for the CIP-named types (BOOL, INT, DINT, LINT, REAL,
// LREAL, ...); Modbus Application Protocol V1.1b3 Sec. 4.3 (Data Model) for
// coils/registers.
/// Protocol-agnostic hint describing the kind of data in a [`Value`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum DataType {
    /// No type information is available.
    #[default]
    Unknown = 0,
    // Ref: CIP Vol. 1 Appendix C, BOOL (section unverified); Modbus coil.
    /// Boolean (coil, discrete input, BOOL tag).
    Bool = 1,
    // Ref: CIP Vol. 1 Appendix C, INT (section unverified).
    /// Signed 16-bit integer.
    Int16 = 2,
    // Ref: CIP Vol. 1 Appendix C, UINT (section unverified); Modbus register.
    /// Unsigned 16-bit integer (Modbus register).
    Uint16 = 3,
    // Ref: CIP Vol. 1 Appendix C, DINT (section unverified).
    /// Signed 32-bit integer (CIP DINT).
    Int32 = 4,
    // Ref: CIP Vol. 1 Appendix C, UDINT (section unverified).
    /// Unsigned 32-bit integer (CIP UDINT).
    Uint32 = 5,
    // Ref: CIP Vol. 1 Appendix C, LINT (section unverified).
    /// Signed 64-bit integer (CIP LINT).
    Int64 = 6,
    // Ref: CIP Vol. 1 Appendix C, ULINT (section unverified).
    /// Unsigned 64-bit integer (CIP ULINT).
    Uint64 = 7,
    // Ref: CIP Vol. 1 Appendix C, REAL (IEEE 754 single; section unverified).
    /// 32-bit float (CIP REAL).
    Float32 = 8,
    // Ref: CIP Vol. 1 Appendix C, LREAL (IEEE 754 double; section unverified).
    /// 64-bit float (CIP LREAL).
    Float64 = 9,
    /// String value.
    String = 10,
    /// Opaque byte sequence (multi-register reads, structs, anything else).
    Bytes = 11,
}

impl DataType {
    // Implementation detail (not spec): Go's `DataType(255)` formatting for
    // values outside the enum.
    /// Converts a raw byte to a `DataType`, `None` if out of range.
    pub fn from_u8(v: u8) -> Option<DataType> {
        Some(match v {
            0 => DataType::Unknown,
            1 => DataType::Bool,
            2 => DataType::Int16,
            3 => DataType::Uint16,
            4 => DataType::Int32,
            5 => DataType::Uint32,
            6 => DataType::Int64,
            7 => DataType::Uint64,
            8 => DataType::Float32,
            9 => DataType::Float64,
            10 => DataType::String,
            11 => DataType::Bytes,
            _ => return None,
        })
    }

    /// Formats a raw byte like Go's `DataType.String()`, including the
    /// `DataType(n)` form for unknown values.
    pub fn name_of(v: u8) -> String {
        match DataType::from_u8(v) {
            Some(t) => t.to_string(),
            None => format!("DataType({v})"),
        }
    }
}

impl fmt::Display for DataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DataType::Unknown => "unknown",
            DataType::Bool => "bool",
            DataType::Int16 => "int16",
            DataType::Uint16 => "uint16",
            DataType::Int32 => "int32",
            DataType::Uint32 => "uint32",
            DataType::Int64 => "int64",
            DataType::Uint64 => "uint64",
            DataType::Float32 => "float32",
            DataType::Float64 => "float64",
            DataType::String => "string",
            DataType::Bytes => "bytes",
        })
    }
}

// Ref: Modbus Application Protocol V1.1b3, Sec. 4.2 Data Encoding (big-endian);
// CIP Vol. 1, Sec. C-1 / Vol. 2 Sec. 2-3 (little-endian encoding of CIP and
// encapsulation data; section numbers unverified).
/// Byte order of the raw data in a [`Value`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ByteOrder {
    /// Byte order was not determined.
    #[default]
    Unspecified,
    // Ref: Modbus Application Protocol V1.1b3, Sec. 4.2 Data Encoding.
    /// Big-endian (Modbus).
    BigEndian,
    // Ref: CIP Vol. 1 (little-endian data encoding; section unverified).
    /// Little-endian (EtherNet/IP CIP).
    LittleEndian,
}

impl fmt::Display for ByteOrder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ByteOrder::BigEndian => "big-endian",
            ByteOrder::LittleEndian => "little-endian",
            ByteOrder::Unspecified => "unspecified",
        })
    }
}

// Implementation detail (not spec): protocol-agnostic addressing.
/// Identifies a readable/writable location on a controller. Protocol
/// implementations encode native addressing (Modbus: area/address/quantity;
/// EtherNet/IP: tag name, element count).
pub trait DataPoint: fmt::Debug + Send + Sync {
    /// Human-readable representation (Go `String()`).
    fn describe(&self) -> String;

    /// Rust stand-in for Go's `dp.(TypedDataPoint)` assertion: implementations
    /// that carry type metadata return `Some(self)`.
    fn as_typed(&self) -> Option<&dyn TypedDataPoint> {
        None
    }

    // Implementation detail (not spec): Rust stand-in for Go's concrete-type assertion
    // (`dp.(Tag)`, `dp.(*pccc.DataPoint)`). Concrete data point types return `Some(self)` so a
    // protocol client can recover its own type with `downcast_ref`.
    /// Returns `self` as `&dyn Any` so protocol clients can downcast to their own data point type.
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        None
    }
}

// Implementation detail (not spec): optional type metadata on a data point.
/// Optional extension of [`DataPoint`] carrying a type hint.
pub trait TypedDataPoint: DataPoint {
    /// The expected data type for this data point.
    fn data_type(&self) -> DataType;
}

// Implementation detail (not spec): result of a read.
/// Result of reading a data point.
#[derive(Debug, Clone, Default)]
pub struct Value {
    /// The data point that was read.
    pub data_point: Option<Arc<dyn DataPoint>>,
    /// Raw bytes returned by the protocol layer.
    pub raw: Vec<u8>,
    /// Type hint for `raw` (may be [`DataType::Unknown`]).
    pub data_type: DataType,
    /// Byte order of `raw`.
    pub byte_order: ByteOrder,
}

impl Value {
    /// Creates a value with only raw bytes (other fields default).
    pub fn from_raw(raw: Vec<u8>) -> Value {
        Value { raw, ..Value::default() }
    }

    /// Creates a value with raw bytes and byte order.
    pub fn with_order(raw: Vec<u8>, byte_order: ByteOrder) -> Value {
        Value { raw, byte_order, ..Value::default() }
    }

    /// True if any byte is nonzero; false when empty.
    pub fn bool(&self) -> bool {
        self.raw.iter().any(|&b| b != 0)
    }

    // Decodes 2/4/8 byte unsigned using the byte order (checked slicing).
    fn read_u(&self, n: usize) -> Option<u64> {
        let b = self.raw.get(..n)?;
        let mut buf = [0u8; 8];
        match self.byte_order {
            ByteOrder::BigEndian => {
                buf[8 - n..].copy_from_slice(b);
                Some(u64::from_be_bytes(buf))
            }
            ByteOrder::LittleEndian => {
                buf[..n].copy_from_slice(b);
                Some(u64::from_le_bytes(buf))
            }
            ByteOrder::Unspecified => None,
        }
    }

    /// Signed 64-bit integer for 1, 2, 4 or 8 byte values. Multi-byte values
    /// require a byte order.
    pub fn int(&self) -> Result<i64> {
        let n = self.raw.len();
        match n {
            1 => Ok(self.raw[0] as i8 as i64),
            2 => self.read_u(2).map(|v| v as u16 as i16 as i64).ok_or(Error::ByteOrderRequired(n)),
            4 => self.read_u(4).map(|v| v as u32 as i32 as i64).ok_or(Error::ByteOrderRequired(n)),
            8 => self.read_u(8).map(|v| v as i64).ok_or(Error::ByteOrderRequired(n)),
            _ => Err(Error::CannotInterpretInt(n)),
        }
    }

    /// Unsigned 64-bit integer for 1, 2, 4 or 8 byte values.
    pub fn uint(&self) -> Result<u64> {
        let n = self.raw.len();
        match n {
            1 => Ok(self.raw[0] as u64),
            2 | 4 | 8 => self.read_u(n).ok_or(Error::ByteOrderRequired(n)),
            _ => Err(Error::CannotInterpretUint(n)),
        }
    }

    // Ref: CIP Vol. 1 Appendix C, REAL = IEEE 754 binary32 (section unverified).
    /// 32-bit float using the value's byte order.
    pub fn float32(&self) -> Result<f32> {
        if self.raw.len() != 4 {
            return Err(Error::WrongSize("float32", 4, self.raw.len()));
        }
        self.read_u(4).map(|v| f32::from_bits(v as u32)).ok_or(Error::ByteOrderRequiredFloat("float32"))
    }

    // Ref: CIP Vol. 1 Appendix C, LREAL = IEEE 754 binary64 (section unverified).
    /// 64-bit float using the value's byte order.
    pub fn float64(&self) -> Result<f64> {
        if self.raw.len() != 8 {
            return Err(Error::WrongSize("float64", 8, self.raw.len()));
        }
        self.read_u(8).map(f64::from_bits).ok_or(Error::ByteOrderRequiredFloat("float64"))
    }
}

// Implementation detail (not spec): read interface.
/// Reads data points from a controller.
pub trait Reader: Send + Sync {
    /// Reads the given points; the result has one [`Value`] per input, in
    /// order. `ctx` supplies cancellation/deadline.
    fn read(&self, ctx: &Context, points: &[Arc<dyn DataPoint>]) -> Result<Vec<Value>>;
}

// Implementation detail (not spec): write interface.
/// Writes data to a controller.
pub trait Writer: Send + Sync {
    /// Writes `data` to `point`. The caller encodes `data` in the byte order
    /// the target protocol expects.
    fn write(&self, ctx: &Context, point: &dyn DataPoint, data: &[u8]) -> Result<()>;
}

// Implementation detail (not spec): connection-oriented PLC abstraction.
/// A connection to a controller: open, close, read and write. For
/// protocol-specific features use the concrete client types.
pub trait Plc: Reader + Writer {
    /// Establishes the underlying protocol session.
    fn connect(&self, ctx: &Context) -> Result<()>;
    /// Gracefully tears down the session.
    fn disconnect(&self, ctx: &Context) -> Result<()>;
    /// Whether the connection is currently active.
    fn is_connected(&self) -> bool;
}

#[cfg(test)]
#[allow(clippy::approx_constant)]
mod tests {
    use super::*;

    #[test]
    fn data_type_string() {
        let tests = [
            (DataType::Unknown as u8, "unknown"),
            (DataType::Bool as u8, "bool"),
            (DataType::Uint16 as u8, "uint16"),
            (DataType::Int32 as u8, "int32"),
            (DataType::Float32 as u8, "float32"),
            (DataType::Bytes as u8, "bytes"),
            (255, "DataType(255)"),
        ];
        for (dt, want) in tests {
            assert_eq!(DataType::name_of(dt), want);
        }
    }

    #[test]
    fn byte_order_string() {
        assert_eq!(ByteOrder::Unspecified.to_string(), "unspecified");
        assert_eq!(ByteOrder::BigEndian.to_string(), "big-endian");
        assert_eq!(ByteOrder::LittleEndian.to_string(), "little-endian");
    }

    #[test]
    fn value_bool() {
        let tests: [(&str, &[u8], bool); 6] = [
            ("nil", &[], false),
            ("empty", &[], false),
            ("zero byte", &[0], false),
            ("nonzero byte", &[1], true),
            ("multi zero", &[0, 0, 0], false),
            ("multi with nonzero", &[0, 0, 1], true),
        ];
        for (name, raw, want) in tests {
            assert_eq!(Value::from_raw(raw.to_vec()).bool(), want, "{name}");
        }
    }

    #[test]
    fn value_int_big_endian() {
        let v = Value::with_order(vec![0xFF], ByteOrder::BigEndian);
        assert_eq!(v.int().unwrap(), -1);
        let v = Value::with_order(0x8000u16.to_be_bytes().to_vec(), ByteOrder::BigEndian);
        assert_eq!(v.int().unwrap(), -32768);
        let v = Value::with_order(42u32.to_be_bytes().to_vec(), ByteOrder::BigEndian);
        assert_eq!(v.int().unwrap(), 42);
    }

    #[test]
    fn value_int_little_endian() {
        let v = Value::with_order(99u32.to_le_bytes().to_vec(), ByteOrder::LittleEndian);
        assert_eq!(v.int().unwrap(), 99);
    }

    #[test]
    fn value_int_no_byte_order() {
        let v = Value::from_raw(vec![0x00, 0x01]);
        assert!(v.int().is_err(), "expected error for unspecified byte order on 2-byte value");
    }

    #[test]
    fn value_uint() {
        let v = Value::with_order(0x1234u16.to_be_bytes().to_vec(), ByteOrder::BigEndian);
        assert_eq!(v.uint().unwrap(), 0x1234);
    }

    #[test]
    fn value_float32() {
        let v = Value::with_order(3.14f32.to_bits().to_le_bytes().to_vec(), ByteOrder::LittleEndian);
        assert_eq!(v.float32().unwrap(), 3.14f32);
    }

    #[test]
    fn value_float64() {
        let v = Value::with_order(2.718f64.to_bits().to_be_bytes().to_vec(), ByteOrder::BigEndian);
        assert_eq!(v.float64().unwrap(), 2.718);
    }

    #[test]
    fn value_float32_wrong_size() {
        let v = Value::with_order(vec![1, 2, 3], ByteOrder::LittleEndian);
        assert!(v.float32().is_err(), "expected error for 3-byte float32");
    }

    #[test]
    fn value_int_unsupported_size() {
        let v = Value::with_order(vec![1, 2, 3], ByteOrder::BigEndian);
        assert!(v.int().is_err(), "expected error for 3-byte int");
    }

    #[test]
    fn error_messages_match_go() {
        assert_eq!(Error::ByteOrderRequired(2).to_string(), "plc: byte order required for 2-byte value");
        assert_eq!(Error::CannotInterpretInt(3).to_string(), "plc: cannot interpret 3 bytes as integer");
        assert_eq!(Error::WrongSize("float32", 4, 3).to_string(), "plc: expected 4 bytes for float32, got 3");
    }

    #[test]
    fn context_cancel_and_deadline() {
        let c = Context::background();
        assert!(!c.is_done());
        let child = c.with_timeout(Duration::from_millis(0));
        assert!(child.is_expired());
        c.cancel();
        assert!(child.is_cancelled());
        assert!(matches!(c.err(), Some(Error::Cancelled)));
    }
}
