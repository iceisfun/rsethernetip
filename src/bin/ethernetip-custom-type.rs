//! ethernetip-custom-type: registers a custom CIP structure type with the type registry. Port of
//! Go `examples/ethernetip/custom_type`.
//!
//! Some PLC structures (add-on-instruction types, vendor timers) are not built in. A type that
//! implements `Marshaler` + `Unmarshaler` + `TypeCodec` and is registered with
//! `cip::register_type` gets a readable `DataType` name, can be read with the typed helpers
//! (`read_typed::<T>`) and written with `write_tag`.
//!
//! The example type "SET_ON_3_TMR" (code 0x2F83) is a 12-byte timer: 32 status bits (EN, EN2,
//! EN3, TT, DN at bits 31, 28, 27, 30, 29), PRE (DINT ms), ACC (DINT ms). Without `-addr` it runs
//! an offline demo of marshal/unmarshal and registry lookups.
//!
//! Ref: Rockwell 1756-PM020 Logix 5000 Data Access - structure data type codes (0x02A0 plus
//! structure handle; layout section unverified); CIP Vol. 1, Appendix C data type reporting
//! (section unverified). The 0x2F83 code and bit layout are an application-specific example,
//! not defined by any spec.
//!
//! Usage:
//!   ethernetip-custom-type                       # offline demo
//!   ethernetip-custom-type -addr 192.168.1.10:44818 -tag MyCustomTimer

use std::time::Duration;

use rsethernetip::cip::{
    self, go_type_to_cip_type, lookup_type, register_type, CipError, DataType, Marshaler, TypeCodec, Unmarshaler,
};
use rsethernetip::cli::{self, Cli};
use rsethernetip::client;
use rsethernetip::conn::{format_dump, Direction};
use rsethernetip::options::{with_hex_dump, with_retries};
use rsethernetip::plc::Context;

// Implementation detail (not spec): application-defined type code for the example structure.
const SET_ON_3_CODE: DataType = DataType(0x2F83);

// Implementation detail (not spec): example status-word bit positions.
const SET_ON_3_EN: u32 = 31;
const SET_ON_3_EN2: u32 = 28;
const SET_ON_3_EN3: u32 = 27;
const SET_ON_3_TT: u32 = 30;
const SET_ON_3_DN: u32 = 29;

/// Example custom structure: a timer with three enable bits.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SetOn3Timer {
    pre: i32,
    acc: i32,
    en: bool,
    en2: bool,
    en3: bool,
    tt: bool,
    dn: bool,
}

// Implementation detail (not spec): Go `CIPType()` and `String()`.
impl TypeCodec for SetOn3Timer {
    fn cip_type(&self) -> DataType {
        SET_ON_3_CODE
    }

    fn display_name(&self) -> Option<String> {
        Some("SET_ON_3_TMR".to_string())
    }
}

// Ref: example layout - bytes 0..4 status bits, 4..8 PRE, 8..12 ACC, little-endian (CIP Vol. 1,
// Appendix C little-endian encoding, section unverified).
impl Unmarshaler for SetOn3Timer {
    fn unmarshal_cip(&mut self, data: &[u8]) -> cip::Result<()> {
        if data.len() < 12 {
            return Err(CipError::Other(format!("SET_ON_3_TMR: need 12 bytes, got {}", data.len())));
        }
        let status = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        self.pre = i32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        self.acc = i32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        self.en = status & (1 << SET_ON_3_EN) != 0;
        self.en2 = status & (1 << SET_ON_3_EN2) != 0;
        self.en3 = status & (1 << SET_ON_3_EN3) != 0;
        self.tt = status & (1 << SET_ON_3_TT) != 0;
        self.dn = status & (1 << SET_ON_3_DN) != 0;
        Ok(())
    }
}

impl Marshaler for SetOn3Timer {
    fn marshal_cip(&self) -> cip::Result<Vec<u8>> {
        let mut status = 0u32;
        for (set, bit) in [
            (self.en, SET_ON_3_EN),
            (self.en2, SET_ON_3_EN2),
            (self.en3, SET_ON_3_EN3),
            (self.tt, SET_ON_3_TT),
            (self.dn, SET_ON_3_DN),
        ] {
            if set {
                status |= 1 << bit;
            }
        }
        let mut buf = Vec::with_capacity(12);
        buf.extend_from_slice(&status.to_le_bytes());
        buf.extend_from_slice(&self.pre.to_le_bytes());
        buf.extend_from_slice(&self.acc.to_le_bytes());
        Ok(buf)
    }
}

fn main() {
    // Register at start-up; the registry panics on a duplicate code (as in Go's init()).
    register_type(SET_ON_3_CODE, || Box::new(SetOn3Timer::default()));

    let args = Cli::new("ethernetip-custom-type", "Registers and reads a custom CIP struct type.")
        .flag("addr", "", "PLC address (host:port). If empty, runs offline demo")
        .flag("tag", "MyCustomTimer", "Tag name to read")
        .parse_env();
    let addr = args.str("addr").to_string();
    let tag = args.str("tag").to_string();

    if addr.is_empty() {
        offline_demo();
        return;
    }

    let ctx = Context::background().with_timeout(Duration::from_secs(10));
    // Hex dump to stdout shows the raw struct bytes on the wire.
    let client = match client::connect(&ctx, &addr, vec![with_retries(2).into(), with_hex_dump(std::io::stdout()).into()]) {
        Ok(c) => c,
        Err(e) => cli::fatal(format!("connect: {e}")),
    };

    // read_typed strips the type header and calls unmarshal_cip on the 12 data bytes.
    let val = match client::read_typed::<SetOn3Timer>(&client, &ctx, &tag) {
        Ok(v) => v,
        Err(e) => cli::fatal(format!("read {tag:?}: {e}")),
    };
    println!("\n{tag}:");
    print_set_on3_timer(&val);
    let _ = client.close();
}

// Implementation detail (not spec): works without a PLC.
fn offline_demo() {
    println!("=== Custom CIP Type Registry Demo ===");
    println!();

    // DataType Display consults the registry; the array flag 0x8000 appends "[]".
    println!("DataType(0x2F83).String() = {}", DataType(0x2F83));
    println!("DataType(0xAF83).String() = {}  (array variant)", DataType(0xAF83));
    println!();

    let codec = match lookup_type(SET_ON_3_CODE) {
        Some(c) => c,
        None => cli::fatal("LookupType returned nil - registration failed"),
    };
    println!(
        "LookupType(0x2F83) -> codec for 0x{:04X} ({})",
        codec.cip_type().0,
        codec.display_name().unwrap_or_default()
    );
    println!();

    let original = SetOn3Timer { pre: 8000, acc: 0, en: true, en2: true, en3: false, tt: true, dn: false };
    let encoded = match original.marshal_cip() {
        Ok(e) => e,
        Err(e) => cli::fatal(format!("MarshalCIP: {e}")),
    };
    println!("Encoded wire bytes ({} bytes):", encoded.len());
    println!();
    print!("{}", format_dump(&encoded, Direction::Write));
    println!();

    let mut decoded = SetOn3Timer::default();
    if let Err(e) = decoded.unmarshal_cip(&encoded) {
        cli::fatal(format!("UnmarshalCIP: {e}"));
    }
    println!("Decoded fields:");
    print_set_on3_timer(&decoded);

    let dt = match go_type_to_cip_type(&decoded) {
        Ok(d) => d,
        Err(e) => cli::fatal(format!("GoTypeToCIPType: {e}")),
    };
    println!("\nGoTypeToCIPType(*SetOn3Timer) = {dt} (0x{:04X})", dt.0);

    println!();
    println!("Simulated ListTags output:");
    println!("  {:<10}  {:<40}  Type (0x{:04X})", "Instance", "Name", 0);
    println!("  {:<10}  {:<40}  ---- (0x{:04X})", "--------", "----", 0);
    println!("  {:<10}  {:<40}  {} (0x{:04X})", 432, "MyCustomTimer", DataType(0xAF83), 0xAF83u16);
    println!("  {:<10}  {:<40}  {} (0x{:04X})", 100, "MyDINT", DataType(0x00C4), 0x00C4u16);
}

fn print_set_on3_timer(s: &SetOn3Timer) {
    print!("  PRE: {} ms", s.pre);
    if s.pre > 0 {
        print!("  ({:.1} s)", s.pre as f64 / 1000.0);
    }
    println!();
    print!("  ACC: {} ms", s.acc);
    if s.acc > 0 {
        print!("  ({:.1} s)", s.acc as f64 / 1000.0);
    }
    println!();
    if s.pre > 0 {
        let pct = (s.acc as f64 / s.pre as f64 * 100.0).min(100.0);
        println!("  Progress: {pct:.1}%");
    }
    println!();
    println!("  EN:  {}", s.en);
    println!("  EN2: {}", s.en2);
    println!("  EN3: {}", s.en3);
    println!("  TT:  {}", s.tt);
    println!("  DN:  {}", s.dn);

    if let Ok(encoded) = s.marshal_cip() {
        println!();
        println!("  Raw bytes:");
        for line in format_dump(&encoded, Direction::Write).lines() {
            if !line.is_empty() {
                println!("    {line}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_short_input() {
        let t = SetOn3Timer { pre: 8000, acc: 5, en: true, en2: true, en3: false, tt: true, dn: false };
        let b = t.marshal_cip().unwrap();
        assert_eq!(b.len(), 12);
        let mut d = SetOn3Timer::default();
        d.unmarshal_cip(&b).unwrap();
        assert_eq!(d, t);
        assert!(d.unmarshal_cip(&b[..11]).is_err());
    }
}
