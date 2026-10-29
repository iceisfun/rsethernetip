//! High-level PCCC client. Port of Go `pccc/client.go`.
//!
//! Ref: Allen-Bradley PCCC / DF1 Protocol and Command Set Reference Manual,
//! publication 1770-6.5.16 (typed logical read/write). The CIP Execute_PCCC
//! tunnelling (class 0x67, service 0x4B) is performed by the [`Executor`].

use super::address::{Address, parse_address};
use super::datapoint::File;
use super::frame::{
    FileType, decode_reply, encode_typed_read, encode_typed_write,
};
use super::{PcccError, Result};
use crate::plc::{self, ByteOrder, Context, DataPoint, DataType, Plc, Reader, Value, Writer};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

// Implementation detail (not spec): transport abstraction. Go `Executor`
// interface; the production implementation is the top-level EtherNet/IP
// client, whose ExecutePCCC ships the bytes via CIP service 0x4B and strips
// the requestor ID from the reply. Tests substitute a fake.
/// Minimum interface a [`Client`] needs from its transport.
pub trait Executor: Send + Sync {
    /// Sends a raw PCCC command and returns the raw PCCC reply.
    fn execute_pccc(
        &self,
        ctx: &Context,
        pccc_cmd: &[u8],
    ) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>;

    // Implementation detail (not spec): stands in for Go's
    // `exec.(Connector)` type assertion.
    /// Returns the lifecycle extension if this executor has one.
    fn as_connector(&self) -> Option<&dyn Connector> {
        None
    }
}

// Implementation detail (not spec): optional lifecycle extension of Executor.
/// Optional extension of [`Executor`] participating in the connection
/// lifecycle. When present, [`Client`] delegates to it; otherwise lifecycle
/// methods are no-ops.
pub trait Connector: Send + Sync {
    /// Connects the transport.
    fn connect(&self, ctx: &Context) -> plc::Result<()>;
    /// Disconnects the transport.
    fn disconnect(&self, ctx: &Context) -> plc::Result<()>;
    /// Whether the transport is connected.
    fn is_connected(&self) -> bool;
}

// Implementation detail (not spec): Go has no concrete option values here;
// `Client::new` takes none.
/// High-level PCCC API: parses SLC addresses, builds and decodes PCCC frames,
/// and exposes string-addressed helpers plus [`plc::Reader`] / [`plc::Writer`]
/// over [`File`] data points.
pub struct Client {
    exec: Arc<dyn Executor>,
    // Wrapped to 16 bits on use.
    tns: AtomicU32,
}

impl Client {
    // Implementation detail (not spec): constructor (Go `NewClient`).
    /// Creates a high-level PCCC client backed by `exec`.
    pub fn new(exec: Arc<dyn Executor>) -> Client {
        // Seed the TNS counter with a small non-zero value so the first
        // transaction is easy to spot on a wire trace.
        Client { exec, tns: AtomicU32::new(1) }
    }

    // Ref: PCCC/DF1 manual 1770-6.5.16, TNS is a 16-bit transaction number
    // echoed in the reply. Zero skipped because some SLC controllers treat TNS=0 specially.
    /// Returns a fresh 16-bit transaction number.
    fn next_tns(&self) -> u16 {
        loop {
            let n = self.tns.fetch_add(1, Ordering::SeqCst).wrapping_add(1) as u16;
            if n != 0 {
                return n;
            }
        }
    }

    // ----- string-addressed convenience API -----

    // Ref: PCCC/DF1 manual 1770-6.5.16 typed logical read (FNC 0xA2).
    /// Reads a single value from the given SLC address. The value holds raw
    /// little-endian bytes plus a type hint: N/B/S/I/O/D -> Int16, F ->
    /// Float32, T/C/R sub-fields -> Int16, T/C/R whole -> Bytes (6 bytes),
    /// bit suffix -> Bool.
    pub fn read_address(&self, ctx: &Context, addr: &str) -> Result<Value> {
        self.read_file(ctx, &File { address: addr.to_string(), count: 0 })
    }

    // Ref: PCCC/DF1 manual 1770-6.5.16 typed logical read (FNC 0xA2), byte-size semantics.
    /// Reads `n` consecutive 16-bit words starting at `addr`. No bit suffix.
    pub fn read_words(&self, ctx: &Context, addr: &str, n: i32) -> Result<Vec<i16>> {
        if n < 1 {
            return Err(PcccError::msg(format!("pccc: ReadWords: n must be >= 1, got {n}")));
        }
        if n > 127 {
            return Err(PcccError::msg(format!("pccc: ReadWords: n must be <= 127, got {n}")));
        }
        let a = parse_address(addr)?;
        if a.bit_num >= 0 {
            return Err(PcccError::msg(format!(
                "pccc: ReadWords: bit suffix not supported in {addr:?}"
            )));
        }
        let n = n as usize;
        let raw = self.raw_read(ctx, &a, (n * 2) as i64)?;
        if raw.len() < n * 2 {
            return Err(PcccError::msg(format!(
                "pccc: ReadWords: short reply ({} bytes, want {})",
                raw.len(),
                n * 2
            )));
        }
        Ok(raw.chunks_exact(2).take(n).map(|c| i16::from_le_bytes([c[0], c[1]])).collect())
    }

    // Ref: PCCC/DF1 manual 1770-6.5.16 typed logical write (FNC 0xAA).
    /// Writes a value to the addressed element. The value type must match the
    /// file type: N/B/S/I/O/D take integers/bool, F takes floats, bit
    /// addresses take bool (read-modify-write).
    pub fn write_address(&self, ctx: &Context, addr: &str, v: impl Into<WriteValue>) -> Result<()> {
        let v = v.into();
        let a = parse_address(addr)?;
        if a.bit_num >= 0 {
            let Some(b) = v.as_bool() else {
                return Err(PcccError::msg(format!(
                    "pccc: write to bit {addr}: value {} not coercible to bool",
                    v.type_name()
                )));
            };
            return self.write_bit(ctx, &a, b);
        }
        if a.file_type == FileType::FLOAT {
            let Some(f) = v.as_f32() else {
                return Err(PcccError::msg(format!(
                    "pccc: write to {addr}: value {} not coercible to float32",
                    v.type_name()
                )));
            };
            return self.write_bytes(ctx, &a, &f.to_bits().to_le_bytes());
        }
        let Some(n) = v.as_i16() else {
            return Err(PcccError::msg(format!(
                "pccc: write to {addr}: value {} not coercible to int16",
                v.type_name()
            )));
        };
        self.write_bytes(ctx, &a, &n.to_le_bytes())
    }

    // Ref: PCCC/DF1 manual 1770-6.5.16 typed logical write (FNC 0xAA).
    /// Writes a slice of 16-bit words starting at `addr`. No bit suffix.
    pub fn write_words(&self, ctx: &Context, addr: &str, words: &[i16]) -> Result<()> {
        if words.is_empty() {
            return Err(PcccError::msg("pccc: WriteWords: empty slice"));
        }
        if words.len() > 120 {
            return Err(PcccError::msg(format!(
                "pccc: WriteWords: too many words ({}, max 120)",
                words.len()
            )));
        }
        let a = parse_address(addr)?;
        if a.bit_num >= 0 {
            return Err(PcccError::msg(format!(
                "pccc: WriteWords: bit suffix not supported in {addr:?}"
            )));
        }
        let buf: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        self.write_bytes(ctx, &a, &buf)
    }

    // ----- internals -----

    // Implementation detail (not spec): parses and reads a File data point
    // into a plc::Value, choosing a type hint per file type.
    fn read_file(&self, ctx: &Context, f: &File) -> Result<Value> {
        let a = f.parse()?;
        let count = f.effective_count();
        let size = element_bytes(&a, count);
        let raw = self.raw_read(ctx, &a, size)?;
        let mut val = Value { byte_order: ByteOrder::LittleEndian, ..Value::default() };
        if a.bit_num >= 0 {
            if raw.len() < 2 {
                return Err(PcccError::msg(format!("pccc: bit read returned {} bytes", raw.len())));
            }
            let word = u16::from_le_bytes([raw[0], raw[1]]);
            val.raw = vec![((word >> a.bit_num) & 1) as u8];
            val.data_type = DataType::Bool;
        } else if a.file_type == FileType::FLOAT {
            val.raw = clip(&raw, 4);
            val.data_type = DataType::Float32;
        } else if is_timer_like(a.file_type) && a.sub_element == 0 {
            // Whole 6-byte element.
            val.raw = clip(&raw, 6);
            val.data_type = DataType::Bytes;
        } else {
            val.raw = clip(&raw, size as usize);
            val.data_type =
                if count > 1 || size > 2 { DataType::Bytes } else { DataType::Int16 };
        }
        Ok(val)
    }

    // Ref: PCCC/DF1 manual 1770-6.5.16 typed logical read (FNC 0xA2).
    /// Encodes a typed-logical read of `byte_size` bytes at `a` and returns the
    /// raw data bytes from the PCCC reply.
    fn raw_read(&self, ctx: &Context, a: &Address, byte_size: i64) -> Result<Vec<u8>> {
        if !(1..=240).contains(&byte_size) {
            return Err(PcccError::msg(format!("pccc: read size {byte_size} out of range [1,240]")));
        }
        let tns = self.next_tns();
        let cmd = encode_typed_read(
            tns,
            byte_size,
            a.file_number,
            a.file_type,
            a.element,
            a.sub_element,
        )?;
        let raw_reply = self.exec.execute_pccc(ctx, &cmd).map_err(PcccError::Exec)?;
        Ok(decode_reply(&raw_reply)?.data)
    }

    // Ref: PCCC/DF1 manual 1770-6.5.16 typed logical write (FNC 0xAA).
    /// Typed-logical write of `data` at the addressed element/sub-element.
    fn write_bytes(&self, ctx: &Context, a: &Address, data: &[u8]) -> Result<()> {
        let tns = self.next_tns();
        let cmd = encode_typed_write(
            tns,
            a.file_number,
            a.file_type,
            a.element,
            a.sub_element,
            data,
        )?;
        let raw_reply = self.exec.execute_pccc(ctx, &cmd).map_err(PcccError::Exec)?;
        decode_reply(&raw_reply)?;
        Ok(())
    }

    // Implementation detail (not spec): read-modify-write of a single bit.
    // Most SLC firmware has a dedicated bit-write command, but RMW is
    // portable across the family and needs no extra FNC code.
    fn write_bit(&self, ctx: &Context, a: &Address, on: bool) -> Result<()> {
        let word_addr = Address { bit_num: -1, ..*a };
        let raw = self.raw_read(ctx, &word_addr, 2)?;
        if raw.len() < 2 {
            return Err(PcccError::msg(format!("pccc: write bit: short read ({} bytes)", raw.len())));
        }
        let mut word = u16::from_le_bytes([raw[0], raw[1]]);
        let mask = 1u16 << a.bit_num;
        if on {
            word |= mask;
        } else {
            word &= !mask;
        }
        self.write_bytes(ctx, &word_addr, &word.to_le_bytes())
    }
}

// Implementation detail (not spec): converts a pccc error to the plc layer.
fn to_plc(e: PcccError) -> plc::Error {
    plc::Error::other(e)
}

// Implementation detail (not spec): recovers a File from a DataPoint (Go type
// assertion `dp.(File)`) via DataPoint::as_any.
fn as_file(dp: &dyn DataPoint) -> Result<File> {
    dp.as_any().and_then(|a| a.downcast_ref::<File>()).cloned().ok_or_else(|| {
        PcccError::msg(format!("pccc: expected File DataPoint, got {}", dp.describe()))
    })
}

impl Reader for Client {
    // Implementation detail (not spec): plc::Reader. Each point must be a
    // File; results preserve input order.
    fn read(&self, ctx: &Context, points: &[Arc<dyn DataPoint>]) -> plc::Result<Vec<Value>> {
        let mut out = Vec::with_capacity(points.len());
        for dp in points {
            let f = as_file(dp.as_ref()).map_err(to_plc)?;
            let mut v = self.read_file(ctx, &f).map_err(to_plc)?;
            v.data_point = Some(Arc::new(f));
            out.push(v);
        }
        Ok(out)
    }
}

impl Writer for Client {
    // Implementation detail (not spec): plc::Writer. `data` is little-endian
    // matching the file type. For bit addresses data[0] is the boolean value
    // and a read-modify-write cycle is performed.
    fn write(&self, ctx: &Context, point: &dyn DataPoint, data: &[u8]) -> plc::Result<()> {
        let f = as_file(point).map_err(to_plc)?;
        let a = f.parse().map_err(to_plc)?;
        if a.bit_num >= 0 {
            if data.is_empty() {
                return Err(to_plc(PcccError::msg(format!(
                    "pccc: write to bit {}: empty data",
                    f.string()
                ))));
            }
            return self.write_bit(ctx, &a, data[0] != 0).map_err(to_plc);
        }
        self.write_bytes(ctx, &a, data).map_err(to_plc)
    }
}

impl Plc for Client {
    // Implementation detail (not spec): delegates to the executor's
    // Connector when present; otherwise a no-op.
    fn connect(&self, ctx: &Context) -> plc::Result<()> {
        match self.exec.as_connector() {
            Some(c) => c.connect(ctx),
            None => Ok(()),
        }
    }

    fn disconnect(&self, ctx: &Context) -> plc::Result<()> {
        match self.exec.as_connector() {
            Some(c) => c.disconnect(ctx),
            None => Ok(()),
        }
    }

    // Returns true when there is no lifecycle to track.
    fn is_connected(&self) -> bool {
        match self.exec.as_connector() {
            Some(c) => c.is_connected(),
            None => true,
        }
    }
}

// Ref: SLC element sizes — 16-bit words for N/B/S/I/O/D, 32-bit float for F,
// 3-word (6 byte) timer/counter/control (PCCC/DF1 manual 1770-6.5.16, SLC 500
// Instruction Set Reference 1747-RM001; section unverified).
/// Read byte size for a parsed address with the given element count.
fn element_bytes(a: &Address, count: i32) -> i64 {
    let count = i64::from(count.max(1));
    if a.bit_num >= 0 {
        2
    } else if a.file_type == FileType::FLOAT {
        4 * count
    } else if is_timer_like(a.file_type) {
        if a.sub_element > 0 { 2 * count } else { 6 * count }
    } else {
        2 * count
    }
}

fn is_timer_like(ft: FileType) -> bool {
    ft == FileType::TIMER || ft == FileType::COUNTER || ft == FileType::CONTROL
}

// Implementation detail (not spec): copy of at most `n` leading bytes.
fn clip(b: &[u8], n: usize) -> Vec<u8> {
    b[..b.len().min(n)].to_vec()
}

// Implementation detail (not spec): replaces Go's `any` argument of
// WriteAddress. Variants mirror the Go types the coercion helpers accept
// (Go `int`/`uint` are 64-bit, represented by `Int`/`Uint`).
/// A dynamically-typed value for [`Client::write_address`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WriteValue {
    /// Go `bool`.
    Bool(bool),
    /// Go `int`.
    Int(i64),
    /// Go `int16`.
    I16(i16),
    /// Go `int32`.
    I32(i32),
    /// Go `int64`.
    I64(i64),
    /// Go `uint`.
    Uint(u64),
    /// Go `uint16`.
    U16(u16),
    /// Go `uint32`.
    U32(u32),
    /// Go `uint64`.
    U64(u64),
    /// Go `byte`.
    U8(u8),
    /// Go `float32`.
    F32(f32),
    /// Go `float64`.
    F64(f64),
}

macro_rules! write_value_from {
    ($($t:ty => $v:ident),* $(,)?) => {
        $(impl From<$t> for WriteValue {
            fn from(x: $t) -> WriteValue { WriteValue::$v(x) }
        })*
    };
}
write_value_from!(bool => Bool, i16 => I16, i32 => I32, i64 => I64, u16 => U16,
    u32 => U32, u64 => U64, u8 => U8, f32 => F32, f64 => F64);

impl WriteValue {
    // Implementation detail (not spec): Go `%T` name for error messages.
    fn type_name(&self) -> &'static str {
        match self {
            WriteValue::Bool(_) => "bool",
            WriteValue::Int(_) => "int",
            WriteValue::I16(_) => "int16",
            WriteValue::I32(_) => "int32",
            WriteValue::I64(_) => "int64",
            WriteValue::Uint(_) => "uint",
            WriteValue::U16(_) => "uint16",
            WriteValue::U32(_) => "uint32",
            WriteValue::U64(_) => "uint64",
            WriteValue::U8(_) => "uint8",
            WriteValue::F32(_) => "float32",
            WriteValue::F64(_) => "float64",
        }
    }

    // Implementation detail (not spec): Go `boolOf` — bool, or any integer
    // (non-zero == true); floats are not coercible.
    fn as_bool(&self) -> Option<bool> {
        Some(match *self {
            WriteValue::Bool(b) => b,
            WriteValue::Int(x) | WriteValue::I64(x) => x != 0,
            WriteValue::I16(x) => x != 0,
            WriteValue::I32(x) => x != 0,
            WriteValue::Uint(x) | WriteValue::U64(x) => x != 0,
            WriteValue::U16(x) => x != 0,
            WriteValue::U32(x) => x != 0,
            WriteValue::U8(x) => x != 0,
            WriteValue::F32(_) | WriteValue::F64(_) => return None,
        })
    }

    // Implementation detail (not spec): Go `int16Of` with range checking
    // (u16 wraps like Go's int16(x); byte and floats are not coercible).
    fn as_i16(&self) -> Option<i16> {
        match *self {
            WriteValue::I16(x) => Some(x),
            WriteValue::U16(x) => Some(x as i16),
            WriteValue::Int(x) | WriteValue::I64(x) => i16::try_from(x).ok(),
            WriteValue::I32(x) => i16::try_from(x).ok(),
            WriteValue::Uint(x) | WriteValue::U64(x) => i16::try_from(x).ok(),
            WriteValue::U32(x) => i16::try_from(x).ok(),
            WriteValue::Bool(b) => Some(i16::from(b)),
            WriteValue::U8(_) | WriteValue::F32(_) | WriteValue::F64(_) => None,
        }
    }

    // Implementation detail (not spec): Go `float32Of`.
    fn as_f32(&self) -> Option<f32> {
        match *self {
            WriteValue::F32(x) => Some(x),
            WriteValue::F64(x) => Some(x as f32),
            WriteValue::Int(x) => Some(x as f32),
            WriteValue::I16(x) => Some(f32::from(x)),
            WriteValue::I32(x) => Some(x as f32),
            _ => None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::approx_constant)]
mod tests {
    use super::*;
    use crate::pccc::frame::{
        FUNC_PROTECTED_TYPED_LOGICAL_READ as FNC_R, FUNC_PROTECTED_TYPED_LOGICAL_WRITE as FNC_W,
        REPLY_BIT,
    };
    use crate::pccc::timer::decode_timer;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicBool;

    type ExecResult = std::result::Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>;
    type ReplyFn = Box<dyn Fn(&[u8]) -> ExecResult + Send + Sync>;

    // Records every PCCC command and produces canned replies; default
    // replies are success for typed reads (zero bytes) and writes.
    #[derive(Default)]
    struct FakeExecutor {
        sent: Mutex<Vec<Vec<u8>>>,
        reply: Option<ReplyFn>,
    }

    impl FakeExecutor {
        fn with(f: impl Fn(&[u8]) -> ExecResult + Send + Sync + 'static) -> Arc<FakeExecutor> {
            Arc::new(FakeExecutor { sent: Mutex::new(vec![]), reply: Some(Box::new(f)) })
        }
        fn sent(&self) -> Vec<Vec<u8>> {
            self.sent.lock().unwrap().clone()
        }
    }

    impl Executor for FakeExecutor {
        fn execute_pccc(&self, _: &Context, cmd: &[u8]) -> ExecResult {
            self.sent.lock().unwrap().push(cmd.to_vec());
            match &self.reply {
                Some(f) => f(cmd),
                None => Ok(default_success(cmd)),
            }
        }
    }

    fn default_success(req: &[u8]) -> Vec<u8> {
        if req.len() < 5 {
            return vec![];
        }
        let mut out = vec![req[0] | REPLY_BIT, 0, req[2], req[3]];
        if req[4] == FNC_R && req.len() >= 6 {
            out.extend(std::iter::repeat_n(0u8, req[5] as usize));
        }
        out
    }

    fn ok(req: &[u8], payload: &[u8]) -> ExecResult {
        let mut v = vec![req[0] | REPLY_BIT, 0x00, req[2], req[3]];
        v.extend_from_slice(payload);
        Ok(v)
    }

    fn ctx() -> Context {
        Context::background()
    }

    #[test]
    fn read_address_integer() {
        let exec = FakeExecutor::with(|r| ok(r, &[0x2A, 0x00]));
        let c = Client::new(exec.clone());
        let v = c.read_address(&ctx(), "N7:0").unwrap();
        assert_eq!(v.int().unwrap(), 42);
        assert_eq!(v.data_type, DataType::Int16);
        assert_eq!(v.byte_order, ByteOrder::LittleEndian);
        let sent = exec.sent();
        assert_eq!(sent.len(), 1);
        let req = &sent[0];
        assert!(req[0] == 0x0F && req[4] == FNC_R);
        assert_eq!(&req[5..10], &[2, 7, FileType::INTEGER.0, 0, 0]);
    }

    #[test]
    fn read_address_float() {
        let bits = 3.14f32.to_bits().to_le_bytes();
        let exec = FakeExecutor::with(move |r| ok(r, &bits));
        let c = Client::new(exec.clone());
        let v = c.read_address(&ctx(), "F8:5").unwrap();
        assert_eq!(v.float32().unwrap(), 3.14);
        assert_eq!(v.data_type, DataType::Float32);
        let req = &exec.sent()[0];
        assert_eq!((req[5], req[6], req[7], req[8]), (4, 8, FileType::FLOAT.0, 5));
    }

    #[test]
    fn read_address_bit() {
        let exec = FakeExecutor::with(|r| ok(r, &[0x14, 0x00]));
        let c = Client::new(exec);
        for (addr, want) in [("B3:0/0", false), ("B3:0/2", true), ("B3:0/3", false), ("B3:0/4", true)] {
            let v = c.read_address(&ctx(), addr).unwrap();
            assert_eq!(v.data_type, DataType::Bool);
            assert_eq!(v.bool(), want, "{addr}");
        }
    }

    #[test]
    fn read_address_timer_whole_element() {
        let payload = [0x00, 0xE0, 0xE8, 0x03, 0xFA, 0x00];
        let exec = FakeExecutor::with(move |r| ok(r, &payload));
        let c = Client::new(exec.clone());
        let v = c.read_address(&ctx(), "T4:0").unwrap();
        assert_eq!(v.data_type, DataType::Bytes);
        assert_eq!(v.raw, payload);
        let tm = decode_timer(&v.raw).unwrap();
        assert!(tm.pre == 1000 && tm.acc == 250 && tm.en(), "{tm}");
        assert_eq!(exec.sent()[0][5], 6);
    }

    #[test]
    fn read_address_timer_sub_field() {
        let exec = FakeExecutor::with(|r| ok(r, &[0xFA, 0x00]));
        let c = Client::new(exec.clone());
        let v = c.read_address(&ctx(), "T4:5.ACC").unwrap();
        assert_eq!(v.data_type, DataType::Int16);
        assert_eq!(v.int().unwrap(), 250);
        let req = &exec.sent()[0];
        assert_eq!(&req[5..10], &[2, 4, FileType::TIMER.0, 5, 2]);
    }

    #[test]
    fn read_words_ok() {
        let exec = FakeExecutor::with(|r| {
            let mut p = vec![];
            for v in [1i16, 2, 3, -4, 5] {
                p.extend_from_slice(&v.to_le_bytes());
            }
            ok(r, &p)
        });
        let c = Client::new(exec.clone());
        let got = c.read_words(&ctx(), "N7:0", 5).unwrap();
        assert_eq!(got, [1, 2, 3, -4, 5]);
        assert_eq!(exec.sent()[0][5], 10);
    }

    #[test]
    fn read_words_rejects_bit_suffix() {
        let c = Client::new(Arc::new(FakeExecutor::default()));
        assert!(c.read_words(&ctx(), "N7:0/2", 3).is_err());
    }

    #[test]
    fn write_address_integer() {
        let exec = Arc::new(FakeExecutor::default());
        let c = Client::new(exec.clone());
        c.write_address(&ctx(), "N7:0", 42i16).unwrap();
        let req = &exec.sent()[0];
        assert_eq!(req[4], FNC_W);
        assert_eq!(&req[5..10], &[2, 7, FileType::INTEGER.0, 0, 0]);
        assert_eq!(&req[10..12], &[0x2A, 0x00]);
    }

    #[test]
    fn write_address_float() {
        let exec = Arc::new(FakeExecutor::default());
        let c = Client::new(exec.clone());
        c.write_address(&ctx(), "F8:5", 2.5f32).unwrap();
        let req = &exec.sent()[0];
        assert_eq!(req[10..14], 2.5f32.to_bits().to_le_bytes());
    }

    #[test]
    fn write_address_bit_read_modify_write() {
        // Initial word = 0x0001; writing /2 = true must write 0x0005.
        let step = AtomicU32::new(0);
        let exec = FakeExecutor::with(move |r| {
            let s = step.fetch_add(1, Ordering::SeqCst);
            if s == 0 {
                if r[4] != FNC_R {
                    return Err("expected read first".into());
                }
                return ok(r, &[0x01, 0x00]);
            }
            if r[4] != FNC_W {
                return Err("expected write second".into());
            }
            ok(r, &[])
        });
        let c = Client::new(exec.clone());
        c.write_address(&ctx(), "B3:0/2", true).unwrap();
        let sent = exec.sent();
        assert_eq!(sent.len(), 2);
        assert_eq!(&sent[1][10..12], &[0x05, 0x00]);
    }

    #[test]
    fn write_address_bit_clear() {
        // Initial word = 0xFFFF; clearing /3 must write 0xFFF7.
        let step = AtomicU32::new(0);
        let exec = FakeExecutor::with(move |r| {
            if step.fetch_add(1, Ordering::SeqCst) == 0 { ok(r, &[0xFF, 0xFF]) } else { ok(r, &[]) }
        });
        let c = Client::new(exec.clone());
        c.write_address(&ctx(), "N7:5/3", false).unwrap();
        assert_eq!(&exec.sent()[1][10..12], &[0xF7, 0xFF]);
    }

    #[test]
    fn write_address_coercion_errors() {
        let c = Client::new(Arc::new(FakeExecutor::default()));
        let e = c.write_address(&ctx(), "N7:0", 70000i64).unwrap_err();
        assert_eq!(e.to_string(), "pccc: write to N7:0: value int64 not coercible to int16");
        assert!(c.write_address(&ctx(), "B3:0/1", 1.5f32).is_err());
        assert!(c.write_address(&ctx(), "F8:0", 7u16).is_err());
    }

    #[test]
    fn plc_read_with_file() {
        let exec = FakeExecutor::with(|r| ok(r, &[0x07, 0x00]));
        let c = Client::new(exec);
        let pts: Vec<Arc<dyn DataPoint>> = vec![Arc::new(File::new("N7:1"))];
        let vals = c.read(&ctx(), &pts).unwrap();
        assert_eq!(vals.len(), 1);
        assert_eq!(vals[0].int().unwrap(), 7);
        assert!(vals[0].data_point.is_some());
    }

    #[test]
    fn plc_write_with_file() {
        let exec = Arc::new(FakeExecutor::default());
        let c = Client::new(exec.clone());
        c.write(&ctx(), &File::new("N7:0"), &[0x09, 0x00]).unwrap();
        assert_eq!(&exec.sent()[0][10..12], &[0x09, 0x00]);
    }

    #[derive(Debug)]
    struct NotFile;
    impl DataPoint for NotFile {
        fn describe(&self) -> String {
            "notFile".to_string()
        }
    }

    #[test]
    fn plc_read_rejects_non_file_data_point() {
        let c = Client::new(Arc::new(FakeExecutor::default()));
        let pts: Vec<Arc<dyn DataPoint>> = vec![Arc::new(NotFile)];
        assert!(c.read(&ctx(), &pts).is_err());
        assert!(c.write(&ctx(), &NotFile, &[1, 0]).is_err());
    }

    #[derive(Default)]
    struct LifecycleExec {
        inner: FakeExecutor,
        connect_calls: AtomicU32,
        connected: AtomicBool,
    }

    impl Executor for LifecycleExec {
        fn execute_pccc(&self, ctx: &Context, cmd: &[u8]) -> ExecResult {
            self.inner.execute_pccc(ctx, cmd)
        }
        fn as_connector(&self) -> Option<&dyn Connector> {
            Some(self)
        }
    }

    impl Connector for LifecycleExec {
        fn connect(&self, _: &Context) -> plc::Result<()> {
            self.connect_calls.fetch_add(1, Ordering::SeqCst);
            self.connected.store(true, Ordering::SeqCst);
            Ok(())
        }
        fn disconnect(&self, _: &Context) -> plc::Result<()> {
            self.connected.store(false, Ordering::SeqCst);
            Ok(())
        }
        fn is_connected(&self) -> bool {
            self.connected.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn lifecycle_delegation() {
        let exec = Arc::new(LifecycleExec::default());
        let c = Client::new(exec.clone());
        assert!(!c.is_connected());
        c.connect(&ctx()).unwrap();
        assert_eq!(exec.connect_calls.load(Ordering::SeqCst), 1);
        assert!(c.is_connected());
        c.disconnect(&ctx()).unwrap();
        assert!(!c.is_connected());
    }

    #[test]
    fn no_lifecycle_no_ops() {
        let c = Client::new(Arc::new(FakeExecutor::default()));
        c.connect(&ctx()).unwrap();
        assert!(c.is_connected());
        c.disconnect(&ctx()).unwrap();
    }

    #[test]
    fn tns_skips_zero_and_wraps() {
        let c = Client::new(Arc::new(FakeExecutor::default()));
        assert_eq!(c.next_tns(), 2);
        c.tns.store(0xFFFF, Ordering::SeqCst);
        assert_eq!(c.next_tns(), 1);
    }
}
