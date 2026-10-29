//! Marshal: Rust values to little-endian CIP wire bytes, plus value -> CIP type mapping.
//!
//! Port of Go `cip/encode.go`. Go uses reflection (`binary.Write`) for built-in types; in Rust
//! the same behavior is provided by [`Marshaler`] implementations for the fixed-size primitive
//! types and for slices/arrays/Vecs of them (no length prefix, like `binary.Write`).

use super::registry::TypeCodec;
use super::types::*;

// Ref: ODVA CIP Vol. 1, Appendix C "Data Management" - all multi-byte values are little-endian
// (section unverified).
// Implemented by types that can marshal themselves into CIP binary format. Types implementing
// Marshaler (custom, e.g. Rockwell structures) take the role of Go's `MarshalCIP` override; the
// built-in impls below play the role of the default `binary.Write` encoding.
pub trait Marshaler {
    fn marshal_cip(&self) -> Result<Vec<u8>>;
}

// Ref: CIP Vol. 1, Appendix C - little-endian encoding of elementary types (section unverified).
// Returns the little-endian CIP encoding of `v`.
pub fn marshal<T: Marshaler + ?Sized>(v: &T) -> Result<Vec<u8>> {
    // 1. Marshaler implementations take priority (custom encoding); the primitive impls provide
    //    the default binary.Write behavior.
    v.marshal_cip()
}

// Ref: CIP Vol. 1, Appendix C - BOOL is encoded as a single byte, 0 = false, 1 = true (section
// unverified).
impl Marshaler for bool {
    fn marshal_cip(&self) -> Result<Vec<u8>> {
        Ok(vec![if *self { 1 } else { 0 }])
    }
}

// Ref: CIP Vol. 1, Appendix C - SINT/INT/DINT/LINT/USINT/UINT/UDINT/ULINT/REAL/LREAL are
// fixed-size little-endian values (section unverified).
macro_rules! impl_marshaler_num {
    ($($t:ty),*) => {$(
        impl Marshaler for $t {
            fn marshal_cip(&self) -> Result<Vec<u8>> {
                Ok(self.to_le_bytes().to_vec())
            }
        }
    )*};
}
impl_marshaler_num!(i8, i16, i32, i64, u8, u16, u32, u64, f32, f64);

// Implementation detail (mirrors binary.Write on slices/arrays): elements are concatenated with
// no length prefix.
impl<T: Marshaler> Marshaler for [T] {
    fn marshal_cip(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for e in self {
            out.extend_from_slice(&e.marshal_cip()?);
        }
        Ok(out)
    }
}

impl<T: Marshaler, const N: usize> Marshaler for [T; N] {
    fn marshal_cip(&self) -> Result<Vec<u8>> {
        self.as_slice().marshal_cip()
    }
}

impl<T: Marshaler> Marshaler for Vec<T> {
    fn marshal_cip(&self) -> Result<Vec<u8>> {
        self.as_slice().marshal_cip()
    }
}

// Implementation detail (maps Go's `any` + type switch in GoTypeToCIPType onto a trait).
// Implemented by values with a natural CIP data type code.
pub trait CipTyped {
    fn cip_data_type(&self) -> Result<DataType>;
}

// Ref: Go GoTypeToCIPType - types registered via `registry::register_type` (TypeCodec) report
// their own code; this is checked first in Go, here the blanket impl covers all TypeCodec types.
impl<T: TypeCodec + ?Sized> CipTyped for T {
    fn cip_data_type(&self) -> Result<DataType> {
        Ok(self.cip_type())
    }
}

// Ref: ODVA CIP Vol. 1, Appendix C data type codes (section unverified): BOOL 0xC1.
impl CipTyped for bool {
    fn cip_data_type(&self) -> Result<DataType> {
        Ok(TYPE_BOOL)
    }
}

// Ref: CIP Vol. 1, Appendix C data type codes (section unverified): SINT 0xC2, INT 0xC3,
// DINT 0xC4, LINT 0xC5, USINT 0xC6, UINT 0xC7, UDINT 0xC8, ULINT 0xC9, REAL 0xCA, LREAL 0xCB.
// (u8 maps to USINT, not BYTE; u16 to UINT, not WORD; u64 to ULINT, not LWORD - as in Go.)
macro_rules! impl_cip_typed {
    ($($t:ty => $c:expr),*) => {$(
        impl CipTyped for $t {
            fn cip_data_type(&self) -> Result<DataType> {
                Ok($c)
            }
        }
    )*};
}
impl_cip_typed!(
    i8 => TYPE_SINT,
    i16 => TYPE_INT,
    i32 => TYPE_DINT,
    i64 => TYPE_LINT,
    u8 => TYPE_USINT,
    u16 => TYPE_UINT,
    u32 => TYPE_UDINT,
    u64 => TYPE_ULINT,
    f32 => TYPE_REAL,
    f64 => TYPE_LREAL
);

// Ref: CIP Vol. 1, Appendix C data type codes (section unverified): STRING 0xD0 (default for
// text, as in Go).
impl CipTyped for str {
    fn cip_data_type(&self) -> Result<DataType> {
        Ok(TYPE_STRING)
    }
}

impl CipTyped for String {
    fn cip_data_type(&self) -> Result<DataType> {
        Ok(TYPE_STRING)
    }
}

// Ref: CIP Vol. 1, Appendix C data type codes (section unverified).
// Maps a value's type to the corresponding CIP DataType code (Go `GoTypeToCIPType`). Supports
// bool, all signed/unsigned integer sizes, f32, f64, strings and any TypeCodec. Go's
// "unsupported Go type" error cannot occur: unsupported types simply do not implement CipTyped
// (compile-time error).
pub fn go_type_to_cip_type<T: CipTyped + ?Sized>(v: &T) -> Result<DataType> {
    v.cip_data_type()
}

#[cfg(test)]
#[allow(clippy::approx_constant)]
mod tests {
    use super::*;
    use crate::cip::decode::unmarshal;

    // ===== CIP Data Type Encode/Decode Round-Trips (values from OpENer cipcommontests.cpp) =====
    // Ref: CIP Vol. 1, Appendix C elementary data types, little-endian (section unverified).

    #[test]
    fn encode_decode_bool() {
        let v = false;
        let data = marshal(&v).unwrap();
        assert!(data.len() == 1 && data[0] == 0, "bool false: got {:X?}", data);

        let v = true;
        let data = marshal(&v).unwrap();
        assert!(data.len() == 1 && data[0] == 1, "bool true: got {:X?}", data);

        let mut out = false;
        unmarshal(&[1], &mut out).unwrap();
        assert!(out, "expected true");
    }

    #[test]
    fn encode_decode_usint() {
        let v: u8 = 212;
        let data = marshal(&v).unwrap();
        assert!(data.len() == 1 && data[0] == 212);
        let mut out: u8 = 0;
        unmarshal(&data, &mut out).unwrap();
        assert_eq!(out, 212);
    }

    #[test]
    fn encode_decode_uint() {
        let v: u16 = 42568; // OpENer test value
        let data = marshal(&v).unwrap();
        assert_eq!(data.len(), 2);
        assert_eq!(u16::from_le_bytes([data[0], data[1]]), 42568);
        let mut out: u16 = 0;
        unmarshal(&data, &mut out).unwrap();
        assert_eq!(out, 42568);
    }

    #[test]
    fn encode_decode_udint() {
        let v: u32 = 1653245; // OpENer test value
        let data = marshal(&v).unwrap();
        assert_eq!(data.len(), 4);
        assert_eq!(u32::from_le_bytes(data[..4].try_into().unwrap()), 1653245);
        let mut out: u32 = 0;
        unmarshal(&data, &mut out).unwrap();
        assert_eq!(out, 1653245);
    }

    #[test]
    fn encode_decode_dword() {
        let v: u32 = 5357678; // OpENer test value for CipDword
        let data = marshal(&v).unwrap();
        assert_eq!(data.len(), 4);
        assert_eq!(u32::from_le_bytes(data[..4].try_into().unwrap()), 5357678);
    }

    #[test]
    fn encode_decode_ulint() {
        let v: u64 = 8353457678; // OpENer test value for CipLword/Ulint
        let data = marshal(&v).unwrap();
        assert_eq!(data.len(), 8);
        assert_eq!(u64::from_le_bytes(data[..8].try_into().unwrap()), 8353457678);
        let mut out: u64 = 0;
        unmarshal(&data, &mut out).unwrap();
        assert_eq!(out, 8353457678);
    }

    #[test]
    fn encode_decode_sint() {
        let v: i8 = -42;
        let data = marshal(&v).unwrap();
        assert_eq!(data.len(), 1);
        let mut out: i8 = 0;
        unmarshal(&data, &mut out).unwrap();
        assert_eq!(out, -42);
    }

    #[test]
    fn encode_decode_int() {
        let v: i16 = -12345;
        let data = marshal(&v).unwrap();
        assert_eq!(data.len(), 2);
        let mut out: i16 = 0;
        unmarshal(&data, &mut out).unwrap();
        assert_eq!(out, -12345);
    }

    #[test]
    fn encode_decode_dint() {
        let v: i32 = -100000;
        let data = marshal(&v).unwrap();
        assert_eq!(data.len(), 4);
        let mut out: i32 = 0;
        unmarshal(&data, &mut out).unwrap();
        assert_eq!(out, -100000);
    }

    #[test]
    fn encode_decode_lint() {
        let v: i64 = -9876543210;
        let data = marshal(&v).unwrap();
        assert_eq!(data.len(), 8);
        let mut out: i64 = 0;
        unmarshal(&data, &mut out).unwrap();
        assert_eq!(out, -9876543210);
    }

    #[test]
    fn encode_decode_real() {
        let v: f32 = 3.14;
        let data = marshal(&v).unwrap();
        assert_eq!(data.len(), 4);
        let mut out: f32 = 0.0;
        unmarshal(&data, &mut out).unwrap();
        assert!(((out - 3.14) as f64).abs() <= 0.001, "REAL round-trip: got {}, want ~3.14", out);
    }

    #[test]
    fn encode_decode_lreal() {
        let v: f64 = 2.718281828;
        let data = marshal(&v).unwrap();
        assert_eq!(data.len(), 8);
        let mut out: f64 = 0.0;
        unmarshal(&data, &mut out).unwrap();
        assert!((out - 2.718281828).abs() <= 0.000001, "LREAL round-trip: got {}", out);
    }

    #[test]
    fn encode_decode_word() {
        let v: u16 = 53678; // OpENer test value for CipWord
        let data = marshal(&v).unwrap();
        assert_eq!(data.len(), 2);
        assert_eq!(u16::from_le_bytes([data[0], data[1]]), 53678);
    }

    #[test]
    fn encode_decode_byte() {
        let v: u8 = 173; // OpENer test value for CipByte
        let data = marshal(&v).unwrap();
        assert!(data.len() == 1 && data[0] == 173);
    }

    // ===== GoTypeToCIPType Mapping =====
    // Ref: CIP Vol. 1, Appendix C data type codes (section unverified).
    #[test]
    fn go_type_to_cip_type_mapping() {
        assert_eq!(go_type_to_cip_type(&true).unwrap(), TYPE_BOOL);
        assert_eq!(go_type_to_cip_type(&0i8).unwrap(), TYPE_SINT);
        assert_eq!(go_type_to_cip_type(&0i16).unwrap(), TYPE_INT);
        assert_eq!(go_type_to_cip_type(&0i32).unwrap(), TYPE_DINT);
        assert_eq!(go_type_to_cip_type(&0i64).unwrap(), TYPE_LINT);
        assert_eq!(go_type_to_cip_type(&0u8).unwrap(), TYPE_USINT);
        assert_eq!(go_type_to_cip_type(&0u16).unwrap(), TYPE_UINT);
        assert_eq!(go_type_to_cip_type(&0u32).unwrap(), TYPE_UDINT);
        assert_eq!(go_type_to_cip_type(&0u64).unwrap(), TYPE_ULINT);
        assert_eq!(go_type_to_cip_type(&0f32).unwrap(), TYPE_REAL);
        assert_eq!(go_type_to_cip_type(&0f64).unwrap(), TYPE_LREAL);
        assert_eq!(go_type_to_cip_type("").unwrap(), TYPE_STRING);
    }

    // Go TestGoTypeToCIPTypeUnsupported has no Rust equivalent: unsupported types do not
    // implement CipTyped, so the mapping fails at compile time rather than at run time.

    // CIP string type code check (cpppo): Go string maps to TypeSTRING.
    #[test]
    fn go_type_to_cip_type_string() {
        let dt = go_type_to_cip_type("Hello").unwrap();
        assert_eq!(dt, TYPE_STRING);
        assert_eq!(go_type_to_cip_type(&String::from("Hello")).unwrap(), TYPE_STRING);
    }

    // --- Tests mined from cpppo: CIP data type boundary values ---

    #[test]
    fn encode_decode_lint_boundary() {
        let v: i64 = -1234567890123456789;
        let data = marshal(&v).unwrap();
        assert_eq!(data.len(), 8);
        let mut out: i64 = 0;
        unmarshal(&data, &mut out).unwrap();
        assert_eq!(out, -1234567890123456789);
    }

    #[test]
    fn encode_decode_ulint_max_bit63() {
        // b'\x00\x00\x00\x00\x00\x00\x00\x80' == 2^63
        let v: u64 = 1 << 63;
        let data = marshal(&v).unwrap();
        assert_eq!(data, vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80]);
        let mut out: u64 = 0;
        unmarshal(&data, &mut out).unwrap();
        assert_eq!(out, 1u64 << 63);
    }

    #[test]
    fn encode_decode_lreal_round_trip() {
        let v: f64 = 1.23;
        let data = marshal(&v).unwrap();
        let mut out: f64 = 0.0;
        unmarshal(&data, &mut out).unwrap();
        assert_eq!(out, 1.23);
    }

    // Slices/arrays marshal as concatenated elements (binary.Write behavior; added).
    #[test]
    fn marshal_slice_and_array() {
        assert_eq!(marshal(&[1u16, 2u16]).unwrap(), vec![1, 0, 2, 0]);
        assert_eq!(marshal(&vec![1i32, -1i32]).unwrap(), vec![1, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF]);
    }
}
