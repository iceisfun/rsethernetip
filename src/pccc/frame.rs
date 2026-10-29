//! PCCC framing: file types, typed-logical read/write encoding, reply
//! decoding and status messages. Port of Go `pccc/frame.go`.
//!
//! Ref: Allen-Bradley PCCC / DF1 Protocol and Command Set Reference Manual,
//! publication 1770-6.5.16.

use super::{PcccError, Result};
use std::fmt;

// Ref: Allen-Bradley PCCC / DF1 Protocol manual 1770-6.5.16 (file type codes
// for typed logical read/write; table number unverified).
/// A PCCC data-table file type code. Newtype so unknown codes round-trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct FileType(pub u8);

impl FileType {
    // Ref: PCCC/DF1 manual 1770-6.5.16, file type 0x84 (S, status).
    /// S, status.
    pub const STATUS: FileType = FileType(0x84);
    // Ref: PCCC/DF1 manual 1770-6.5.16, file type 0x85 (B, bit).
    /// B, bit.
    pub const BIT: FileType = FileType(0x85);
    // Ref: PCCC/DF1 manual 1770-6.5.16, file type 0x86 (T, timer).
    /// T, timer (control/PRE/ACC).
    pub const TIMER: FileType = FileType(0x86);
    // Ref: PCCC/DF1 manual 1770-6.5.16, file type 0x87 (C, counter).
    /// C, counter (control/PRE/ACC).
    pub const COUNTER: FileType = FileType(0x87);
    // Ref: PCCC/DF1 manual 1770-6.5.16, file type 0x88 (R, control).
    /// R, generic control.
    pub const CONTROL: FileType = FileType(0x88);
    // Ref: PCCC/DF1 manual 1770-6.5.16, file type 0x89 (N, integer).
    /// N, 16-bit integer.
    pub const INTEGER: FileType = FileType(0x89);
    // Ref: PCCC/DF1 manual 1770-6.5.16, file type 0x8A (F, float).
    /// F, 32-bit IEEE float.
    pub const FLOAT: FileType = FileType(0x8A);
    // Ref: Allen-Bradley PCCC/DF1 manual 1770-6.5.16, file-type code table (O = 0x82; codes from memory, section unverified).
    /// O, output image.
    pub const OUTPUT: FileType = FileType(0x82);
    // Ref: Allen-Bradley PCCC/DF1 manual 1770-6.5.16, file-type code table (I = 0x83; codes from memory, section unverified).
    /// I, input image.
    pub const INPUT: FileType = FileType(0x83);
    // Ref: PCCC/DF1 manual 1770-6.5.16, file type 0x8D (ST, string).
    /// ST, string.
    pub const STRING: FileType = FileType(0x8D);
    // Ref: PCCC/DF1 manual 1770-6.5.16, file type 0x8E (A, ASCII).
    /// A, ASCII.
    pub const ASCII: FileType = FileType(0x8E);
    // Ref: PCCC/DF1 manual 1770-6.5.16, file type 0x8F (D, BCD).
    /// D, BCD.
    pub const BCD: FileType = FileType(0x8F);

    // Ref: SLC 500 file mnemonics (S,B,T,C,R,N,F,O,I,ST,A,D), PCCC/DF1 manual 1770-6.5.16 (section unverified).
    /// SLC mnemonic ("N", "F", "ST", ...); empty for unknown codes.
    pub fn letter(self) -> &'static str {
        FILE_TYPE_TABLE.iter().find(|e| e.0 == self).map(|e| e.1).unwrap_or("")
    }
}

// Implementation detail (not spec): Go `String()` text.
impl fmt::Display for FileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let l = self.letter();
        if !l.is_empty() {
            write!(f, "{}(0x{:02X})", l, self.0)
        } else {
            write!(f, "FileType(0x{:02X})", self.0)
        }
    }
}

// Ref: SLC 500 file mnemonics, PCCC/DF1 manual 1770-6.5.16 (section unverified).
/// Returns the FileType for an SLC mnemonic, case-insensitively.
pub fn file_type_from_letter(letter: &str) -> Option<FileType> {
    let up = letter.to_uppercase();
    FILE_TYPE_TABLE.iter().find(|e| e.1 == up).map(|e| e.0)
}

// Ref: PCCC/DF1 manual 1770-6.5.16, file type code <-> mnemonic mapping.
static FILE_TYPE_TABLE: [(FileType, &str); 12] = [
    (FileType::STATUS, "S"),
    (FileType::BIT, "B"),
    (FileType::TIMER, "T"),
    (FileType::COUNTER, "C"),
    (FileType::CONTROL, "R"),
    (FileType::INTEGER, "N"),
    (FileType::FLOAT, "F"),
    (FileType::OUTPUT, "O"),
    (FileType::INPUT, "I"),
    (FileType::STRING, "ST"),
    (FileType::ASCII, "A"),
    (FileType::BCD, "D"),
];

// Ref: PCCC/DF1 manual 1770-6.5.16, CMD 0x0F with FNC 0xA2/0xAA ("Protected
// Typed Logical Read/Write with 3 Address Fields").
/// PCCC CMD byte used by FNC 0xA2 (read) and 0xAA (write).
pub const CMD_PROTECTED_TYPED_LOGICAL: u8 = 0x0F;

// Ref: PCCC/DF1 manual 1770-6.5.16, FNC 0xA2 Protected Typed Logical Read with 3 Address Fields.
/// FNC code for typed-logical read.
pub const FUNC_PROTECTED_TYPED_LOGICAL_READ: u8 = 0xA2;

// Ref: PCCC/DF1 manual 1770-6.5.16, FNC 0xAA Protected Typed Logical Write with 3 Address Fields.
/// FNC code for typed-logical write.
pub const FUNC_PROTECTED_TYPED_LOGICAL_WRITE: u8 = 0xAA;

// Ref: PCCC/DF1 manual 1770-6.5.16, command-byte bit 6 (0x40) marks a reply.
/// OR-ed into the CMD byte of a PCCC reply.
pub const REPLY_BIT: u8 = 0x40;

// Ref: PCCC/DF1 manual 1770-6.5.16, STS 0xF0 = extended status byte follows.
/// STS value indicating the EXT STS byte carries the real error code.
pub const STATUS_USE_EXT_STS: u8 = 0xF0;

// Ref: PCCC/DF1 manual 1770-6.5.16, command reply format CMD/STS/TNS[/EXT STS]/data.
/// A decoded PCCC reply packet.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Reply {
    /// Request CMD with the reply bit stripped.
    pub command: u8,
    /// PCCC status code (0 = success).
    pub sts: u8,
    /// Transaction number echoed from the request.
    pub tns: u16,
    /// Extended status byte; non-zero only when STS == 0xF0.
    pub ext_sts: u8,
    /// Application payload following the header (may be empty).
    pub data: Vec<u8>,
}

// Ref: PCCC/DF1 manual 1770-6.5.16, STS / EXT STS error codes (Appendix B).
/// A PCCC protocol error: non-zero STS, optionally with an EXT STS code.
/// Protocol-level failure; callers should not retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    /// STS byte.
    pub sts: u8,
    /// EXT STS byte.
    pub ext_sts: u8,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.sts == STATUS_USE_EXT_STS {
            write!(
                f,
                "pccc: STS=0x{:02X} EXT_STS=0x{:02X} ({})",
                self.sts,
                self.ext_sts,
                status_message(self.sts, self.ext_sts)
            )
        } else {
            write!(f, "pccc: STS=0x{:02X} ({})", self.sts, status_message(self.sts, self.ext_sts))
        }
    }
}

impl std::error::Error for Error {}

// Implementation detail (not spec): Go `IsPCCCError` type assertion.
/// Reports whether `e` is a PCCC protocol status error.
pub fn is_pccc_error(e: &PcccError) -> bool {
    matches!(e, PcccError::Status(_))
}

// Ref: PCCC/DF1 manual 1770-6.5.16, Protected Typed Logical Read with 3
// Address Fields (FNC 0xA2): CMD STS TNS(LE) FNC ByteSize File Type Elem SubElem.
/// Encodes a PROTECTED TYPED LOGICAL READ (FNC 0xA2) command; the result is
/// the PCCC message (CMD..end) ready to wrap in an Execute_PCCC CIP request.
/// `byte_size` is the number of data-table bytes to read (1..255).
pub fn encode_typed_read(
    tns: u16,
    byte_size: i64,
    file_num: i64,
    ft: FileType,
    elem: i64,
    sub_elem: i64,
) -> Result<Vec<u8>> {
    validate_address(file_num, elem, sub_elem, ft)?;
    if !(1..=255).contains(&byte_size) {
        return Err(PcccError::msg(format!("pccc: byte size {byte_size} out of range [1,255]")));
    }
    let t = tns.to_le_bytes();
    Ok(vec![
        CMD_PROTECTED_TYPED_LOGICAL,
        0x00, // STS — always 0 in requests
        t[0],
        t[1],
        FUNC_PROTECTED_TYPED_LOGICAL_READ,
        byte_size as u8,
        file_num as u8,
        ft.0,
        elem as u8,
        sub_elem as u8,
    ])
}

// Ref: PCCC/DF1 manual 1770-6.5.16, Protected Typed Logical Write with 3
// Address Fields (FNC 0xAA): CMD STS TNS(LE) FNC ByteSize File Type Elem SubElem Data
// (same layout as FNC 0xA2; typed-logical layout only, section unverified).
/// Encodes a PROTECTED TYPED LOGICAL WRITE (FNC 0xAA) command. `data` is the
/// raw payload; the caller ensures its length matches the addressed element(s).
pub fn encode_typed_write(
    tns: u16,
    file_num: i64,
    ft: FileType,
    elem: i64,
    sub_elem: i64,
    data: &[u8],
) -> Result<Vec<u8>> {
    validate_address(file_num, elem, sub_elem, ft)?;
    if data.is_empty() {
        return Err(PcccError::msg("pccc: write data is empty"));
    }
    if data.len() > 240 {
        // Implementation detail (not spec): conservative cap so a PCCC frame
        // fits after CIP/EIP overhead; callers should chunk before this.
        return Err(PcccError::msg(format!("pccc: write data too large ({} bytes)", data.len())));
    }
    let t = tns.to_le_bytes();
    let mut buf = Vec::with_capacity(10 + data.len());
    buf.extend_from_slice(&[
        CMD_PROTECTED_TYPED_LOGICAL,
        0x00,
        t[0],
        t[1],
        FUNC_PROTECTED_TYPED_LOGICAL_WRITE,
        data.len() as u8, // byte size (data.len() <= 240 checked above)
        file_num as u8,
        ft.0,
        elem as u8,
        sub_elem as u8,
    ]);
    buf.extend_from_slice(data);
    Ok(buf)
}

// Ref: PCCC/DF1 manual 1770-6.5.16, 3-address-field logical addressing (section
// unverified): a single-byte field value of 0xFF introduces a 2-byte LE value, so
// this encoder only emits single-byte values 0..=254 (the 0xFF escape is not implemented).
fn validate_address(file_num: i64, elem: i64, sub_elem: i64, ft: FileType) -> Result<()> {
    if ft.letter().is_empty() {
        return Err(PcccError::msg(format!("pccc: unknown file type 0x{:02X}", ft.0)));
    }
    if !(0..=254).contains(&file_num) {
        return Err(PcccError::msg(format!("pccc: file number {file_num} out of range [0,254]")));
    }
    if !(0..=254).contains(&elem) {
        return Err(PcccError::msg(format!("pccc: element {elem} out of range [0,254]")));
    }
    if !(0..=254).contains(&sub_elem) {
        return Err(PcccError::msg(format!("pccc: sub-element {sub_elem} out of range [0,254]")));
    }
    Ok(())
}

// Ref: PCCC/DF1 manual 1770-6.5.16, reply format CMD(|0x40) STS TNS [EXT STS] data.
/// Parses a PCCC reply frame. On success STS == 0 and `data` is the payload;
/// on non-zero STS the error is [`PcccError::Status`].
pub fn decode_reply(raw: &[u8]) -> Result<Reply> {
    if raw.len() < 4 {
        return Err(PcccError::msg(format!(
            "pccc: reply too short ({} bytes, need >=4)",
            raw.len()
        )));
    }
    if raw[0] & REPLY_BIT == 0 {
        return Err(PcccError::msg(format!("pccc: CMD 0x{:02X} has no reply bit set", raw[0])));
    }
    let mut r = Reply {
        command: raw[0] & !REPLY_BIT,
        sts: raw[1],
        tns: u16::from_le_bytes([raw[2], raw[3]]),
        ..Reply::default()
    };
    let mut rest = &raw[4..];
    if r.sts == STATUS_USE_EXT_STS {
        match rest.split_first() {
            None => {
                return Err(PcccError::msg("pccc: STS=0xF0 but reply missing EXT STS byte"));
            }
            Some((e, tail)) => {
                r.ext_sts = *e;
                rest = tail;
            }
        }
    }
    if r.sts != 0 {
        return Err(PcccError::Status(Error { sts: r.sts, ext_sts: r.ext_sts }));
    }
    r.data = rest.to_vec();
    Ok(r)
}

// Ref: PCCC/DF1 manual 1770-6.5.16, Appendix B (status codes).
/// Human-readable description of a PCCC status. Unknown codes fall back to hex.
pub fn status_message(sts: u8, ext_sts: u8) -> String {
    if sts == 0 {
        return "success".to_string();
    }
    if sts == STATUS_USE_EXT_STS {
        return match EXT_STATUS_MESSAGES.iter().find(|e| e.0 == ext_sts) {
            Some(e) => e.1.to_string(),
            None => format!("extended status 0x{ext_sts:02X}"),
        };
    }
    match LOCAL_STATUS_MESSAGES.iter().find(|e| e.0 == sts) {
        Some(e) => e.1.to_string(),
        None => format!("status 0x{sts:02X}"),
    }
}

// Ref: PCCC/DF1 manual 1770-6.5.16, Appendix B, local (low nibble) and
// remote (high nibble) STS codes merged into one byte-keyed table.
static LOCAL_STATUS_MESSAGES: [(u8, &str); 20] = [
    (0x01, "local: destination node out of buffer space"),
    (0x02, "local: cannot guarantee delivery (link layer)"),
    (0x03, "local: duplicate token holder detected"),
    (0x04, "local: local port disconnected"),
    (0x05, "local: application timed out waiting for response"),
    (0x06, "local: duplicate node detected"),
    (0x07, "local: station is offline"),
    (0x08, "local: hardware fault"),
    (0x10, "remote: illegal command or format"),
    (0x20, "remote: host has a problem and will not communicate"),
    (0x30, "remote: remote node host is missing, disconnected, or shut down"),
    (0x40, "remote: host could not complete function due to hardware fault"),
    (0x50, "remote: addressing problem or memory protect rungs"),
    (0x60, "remote: function not allowed due to command-protection selection"),
    (0x70, "remote: processor is in program mode"),
    (0x80, "remote: compatibility-mode file missing or communication-zone problem"),
    (0x90, "remote: remote node cannot buffer command"),
    (0xA0, "remote: wait ACK (1775-KA buffer full)"),
    (0xB0, "remote: remote node problem due to download"),
    (0xC0, "remote: wait ACK (1775-KA buffer full)"),
];

// Ref: PCCC/DF1 manual 1770-6.5.16, Appendix B, EXT STS table for STS = 0xF0.
static EXT_STATUS_MESSAGES: [(u8, &str); 29] = [
    (0x01, "a field has an illegal value"),
    (0x02, "fewer levels specified in address than minimum"),
    (0x03, "more levels specified in address than system supports"),
    (0x04, "symbol not found"),
    (0x05, "symbol is of improper format"),
    (0x06, "address does not point to something usable"),
    (0x07, "file is wrong size"),
    (0x08, "cannot complete request; situation changed since command started"),
    (0x09, "data or file is too large"),
    (0x0A, "transaction size plus word address is too large"),
    (0x0B, "access denied, improper privilege"),
    (0x0C, "condition cannot be generated; resource is not available"),
    (0x0D, "condition already exists; resource is already available"),
    (0x0E, "command cannot be executed"),
    (0x0F, "histogram overflow"),
    (0x10, "no access"),
    (0x11, "illegal data type"),
    (0x12, "invalid parameter or invalid data"),
    (0x13, "address reference exists to deleted area"),
    (0x14, "command execution failure for unknown reason"),
    (0x15, "data conversion error"),
    (0x16, "scanner not able to communicate with 1771 rack adapter"),
    (0x17, "type mismatch"),
    (0x18, "1771 module response was not valid"),
    (0x19, "duplicated label"),
    (0x1A, "file is open; another node owns it"),
    (0x1B, "another node is the program owner"),
    (0x1E, "data table element protection violation"),
    (0x1F, "temporary internal problem"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_type_codes() {
        let tests = [
            (FileType::STATUS, 0x84),
            (FileType::BIT, 0x85),
            (FileType::TIMER, 0x86),
            (FileType::COUNTER, 0x87),
            (FileType::CONTROL, 0x88),
            (FileType::INTEGER, 0x89),
            (FileType::FLOAT, 0x8A),
            (FileType::OUTPUT, 0x82),
            (FileType::INPUT, 0x83),
            (FileType::STRING, 0x8D),
            (FileType::ASCII, 0x8E),
            (FileType::BCD, 0x8F),
        ];
        for (ft, code) in tests {
            assert_eq!(ft.0, code);
        }
    }

    #[test]
    fn file_type_letter() {
        let tests = [
            (FileType::STATUS, "S"),
            (FileType::BIT, "B"),
            (FileType::TIMER, "T"),
            (FileType::COUNTER, "C"),
            (FileType::CONTROL, "R"),
            (FileType::INTEGER, "N"),
            (FileType::FLOAT, "F"),
            (FileType::OUTPUT, "O"),
            (FileType::INPUT, "I"),
            (FileType::STRING, "ST"),
            (FileType::ASCII, "A"),
            (FileType::BCD, "D"),
        ];
        for (ft, l) in tests {
            assert_eq!(ft.letter(), l);
        }
        assert_eq!(FileType::INTEGER.to_string(), "N(0x89)");
        assert_eq!(FileType(0).to_string(), "FileType(0x00)");
    }

    #[test]
    fn file_type_from_letter_cases() {
        let tests: [(&str, Option<FileType>); 17] = [
            ("S", Some(FileType::STATUS)),
            ("B", Some(FileType::BIT)),
            ("N", Some(FileType::INTEGER)),
            ("F", Some(FileType::FLOAT)),
            ("T", Some(FileType::TIMER)),
            ("C", Some(FileType::COUNTER)),
            ("R", Some(FileType::CONTROL)),
            ("O", Some(FileType::OUTPUT)),
            ("I", Some(FileType::INPUT)),
            ("ST", Some(FileType::STRING)),
            ("A", Some(FileType::ASCII)),
            ("D", Some(FileType::BCD)),
            ("n", Some(FileType::INTEGER)),
            ("st", Some(FileType::STRING)),
            ("", None),
            ("X", None),
            ("NN", None),
        ];
        for (l, want) in tests {
            assert_eq!(file_type_from_letter(l), want, "{l:?}");
        }
    }

    #[test]
    fn pccc_constants() {
        assert_eq!(CMD_PROTECTED_TYPED_LOGICAL, 0x0F);
        assert_eq!(FUNC_PROTECTED_TYPED_LOGICAL_READ, 0xA2);
        assert_eq!(FUNC_PROTECTED_TYPED_LOGICAL_WRITE, 0xAA);
        assert_eq!(REPLY_BIT, 0x40);
        assert_eq!(STATUS_USE_EXT_STS, 0xF0);
    }

    #[test]
    fn encode_typed_read_n7() {
        let got = encode_typed_read(0x1234, 2, 7, FileType::INTEGER, 0, 0).unwrap();
        assert_eq!(got, [0x0F, 0x00, 0x34, 0x12, 0xA2, 0x02, 0x07, 0x89, 0x00, 0x00]);
    }

    #[test]
    fn encode_typed_read_timer_acc() {
        let got = encode_typed_read(0x0001, 2, 4, FileType::TIMER, 5, 2).unwrap();
        assert_eq!(got, [0x0F, 0x00, 0x01, 0x00, 0xA2, 0x02, 0x04, 0x86, 0x05, 0x02]);
    }

    #[test]
    fn encode_typed_read_validates() {
        let i = FileType::INTEGER;
        let cases: [(&str, i64, i64, i64, i64, FileType); 7] = [
            ("zero byte size", 0, 7, 0, 0, i),
            ("byte size > 255", 300, 7, 0, 0, i),
            ("file num > 255", 1, 999, 0, 0, i),
            ("file num negative", 1, -1, 0, 0, i),
            ("elem > 255", 1, 7, 999, 0, i),
            ("sub-elem > 255", 1, 7, 0, 999, i),
            ("unknown file type", 1, 7, 0, 0, FileType(0)),
        ];
        for (name, bs, f, e, s, ft) in cases {
            assert!(encode_typed_read(1, bs, f, ft, e, s).is_err(), "{name}");
        }
    }

    #[test]
    fn encode_typed_write_n7() {
        let got = encode_typed_write(0x0001, 7, FileType::INTEGER, 0, 0, &[0x2A, 0x00]).unwrap();
        assert_eq!(got, [0x0F, 0x00, 0x01, 0x00, 0xAA, 0x02, 0x07, 0x89, 0x00, 0x00, 0x2A, 0x00]);
    }

    #[test]
    fn encode_typed_write_validates() {
        let i = FileType::INTEGER;
        let d: &[u8] = &[0, 0];
        #[allow(clippy::type_complexity)]
        let cases: [(&str, i64, i64, i64, FileType, &[u8]); 6] = [
            ("nil data", 7, 0, 0, i, &[]),
            ("empty data", 7, 0, 0, i, &[]),
            ("file num > 255", 999, 0, 0, i, d),
            ("elem > 255", 7, 999, 0, i, d),
            ("sub-elem > 255", 7, 0, 999, i, d),
            ("unknown file type", 7, 0, 0, FileType(0), d),
        ];
        for (name, f, e, s, ft, data) in cases {
            assert!(encode_typed_write(1, f, ft, e, s, data).is_err(), "{name}");
        }
        assert!(encode_typed_write(1, 7, i, 0, 0, &[0u8; 241]).is_err());
    }

    #[test]
    fn decode_reply_success() {
        let r = decode_reply(&[0x4F, 0x00, 0x34, 0x12, 0x2A, 0x00]).unwrap();
        assert_eq!(r.command, CMD_PROTECTED_TYPED_LOGICAL);
        assert_eq!(r.tns, 0x1234);
        assert_eq!(r.sts, 0);
        assert_eq!(r.ext_sts, 0);
        assert_eq!(r.data, [0x2A, 0x00]);
    }

    #[test]
    fn decode_reply_empty_data() {
        let r = decode_reply(&[0x4F, 0x00, 0x01, 0x00]).unwrap();
        assert!(r.data.is_empty());
        assert_eq!(r.sts, 0);
    }

    #[test]
    fn decode_reply_local_sts_error() {
        let err = decode_reply(&[0x4F, 0x10, 0x34, 0x12]).unwrap_err();
        assert!(is_pccc_error(&err));
        let PcccError::Status(pe) = &err else { panic!("not status") };
        assert_eq!(pe.sts, 0x10);
        assert_eq!(pe.ext_sts, 0);
        assert!(pe.to_string().contains("0x10"), "{pe}");
    }

    #[test]
    fn decode_reply_ext_sts_error() {
        let err = decode_reply(&[0x4F, 0xF0, 0x34, 0x12, 0x04]).unwrap_err();
        let PcccError::Status(pe) = &err else { panic!("not status") };
        assert_eq!((pe.sts, pe.ext_sts), (0xF0, 0x04));
        assert!(pe.to_string().contains("0x04"), "{pe}");
    }

    #[test]
    fn decode_reply_truncated() {
        let cases: [&[u8]; 5] = [
            &[],
            &[0x4F],
            &[0x4F, 0x00],
            &[0x4F, 0x00, 0x34],
            &[0x4F, 0xF0, 0x34, 0x12],
        ];
        for raw in cases {
            assert!(decode_reply(raw).is_err(), "{raw:?}");
        }
    }

    #[test]
    fn decode_reply_rejects_request() {
        let raw = [0x0F, 0x00, 0x34, 0x12, 0xA2, 0x02, 0x07, 0x89, 0x00, 0x00];
        assert!(decode_reply(&raw).is_err());
    }

    #[test]
    fn status_message_known() {
        for (sts, ext, must) in [(0x10, 0x00, "illegal"), (0x70, 0x00, "program mode"), (0xF0, 0x04, "symbol not found")] {
            let msg = status_message(sts, ext);
            assert!(!msg.is_empty());
            assert!(msg.to_lowercase().contains(must), "{msg}");
        }
    }

    #[test]
    fn status_message_unknown() {
        assert!(status_message(0x7B, 0).contains("0x7B"));
    }

    #[test]
    fn encode_decode_round_trip() {
        let req = encode_typed_read(0xBEEF, 2, 7, FileType::INTEGER, 0, 0).unwrap();
        let reply = [req[0] | REPLY_BIT, 0x00, req[2], req[3], 0x2A, 0x00];
        let r = decode_reply(&reply).unwrap();
        assert_eq!(r.tns, 0xBEEF);
    }
}
