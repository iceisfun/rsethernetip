//! CIP elementary types, service/class/data-type/status constants and the
//! CIP-layer error types.
//!
//! Port of Go `cip/types.go`.

use std::fmt;

// ---------------------------------------------------------------------------
// CIP elementary data types
// ---------------------------------------------------------------------------

// Ref: ODVA CIP Vol. 1 (Common Industrial Protocol), Appendix C "Data
// Management" - elementary data types (section unverified).
// USINT is an unsigned 8-bit integer (CIP elementary type).
pub type USINT = u8;

// Ref: ODVA CIP Vol. 1, Appendix C "Data Management" - elementary data types
// (section unverified). UINT is an unsigned 16-bit integer.
pub type UINT = u16;

// Ref: ODVA CIP Vol. 1, Appendix C "Data Management" - elementary data types
// (section unverified). UDINT is an unsigned 32-bit integer.
pub type UDINT = u32;

// Ref: ODVA CIP Vol. 1, Appendix C "Data Management" - elementary data types
// (section unverified). ULINT is an unsigned 64-bit integer.
pub type ULINT = u64;

// Ref: ODVA CIP Vol. 1, Appendix C "Data Management" - elementary data types
// (section unverified). SINT is a signed 8-bit integer.
pub type SINT = i8;

// Ref: ODVA CIP Vol. 1, Appendix C "Data Management" - elementary data types
// (section unverified). INT is a signed 16-bit integer.
pub type INT = i16;

// Ref: ODVA CIP Vol. 1, Appendix C "Data Management" - elementary data types
// (section unverified). DINT is a signed 32-bit integer.
pub type DINT = i32;

// Ref: ODVA CIP Vol. 1, Appendix C "Data Management" - elementary data types
// (section unverified). LINT is a signed 64-bit integer.
pub type LINT = i64;

// Ref: ODVA CIP Vol. 1, Appendix C "Data Management" - elementary data types
// (section unverified). REAL is a 32-bit IEEE 754 float.
pub type REAL = f32;

// Ref: ODVA CIP Vol. 1, Appendix C "Data Management" - elementary data types
// (section unverified). LREAL is a 64-bit IEEE 754 float.
pub type LREAL = f64;

// Ref: ODVA CIP Vol. 1, Appendix C "Data Management" - elementary data types
// (section unverified). BYTE is an 8-bit bit string.
pub type BYTE = u8;

// Ref: ODVA CIP Vol. 1, Appendix C "Data Management" - elementary data types
// (section unverified). WORD is a 16-bit bit string.
pub type WORD = u16;

// Ref: ODVA CIP Vol. 1, Appendix C "Data Management" - elementary data types
// (section unverified). DWORD is a 32-bit bit string.
pub type DWORD = u32;

// Ref: ODVA CIP Vol. 1, Appendix C "Data Management" - elementary data types
// (section unverified). LWORD is a 64-bit bit string.
pub type LWORD = u64;

// ---------------------------------------------------------------------------
// Service codes
// ---------------------------------------------------------------------------

// Ref: ODVA CIP Vol. 1, Appendix A "Explicit Messaging Services" - Common
// Services list (section unverified). Get_Attribute_All.
pub const SERVICE_GET_ATTRIBUTE_ALL: USINT = 0x01;
// Ref: ODVA CIP Vol. 1, Appendix A, Common Services (section unverified). Set_Attribute_All.
pub const SERVICE_SET_ATTRIBUTE_ALL: USINT = 0x02;
// Ref: ODVA CIP Vol. 1, Appendix A, Common Services (section unverified). Get_Attribute_List.
pub const SERVICE_GET_ATTRIBUTE_LIST: USINT = 0x03;
// Ref: ODVA CIP Vol. 1, Appendix A, Common Services (section unverified). Set_Attribute_List.
pub const SERVICE_SET_ATTRIBUTE_LIST: USINT = 0x04;
// Ref: ODVA CIP Vol. 1, Appendix A, Common Services (section unverified). Reset.
pub const SERVICE_RESET: USINT = 0x05;
// Ref: ODVA CIP Vol. 1, Appendix A, Common Services (section unverified). Start.
pub const SERVICE_START: USINT = 0x06;
// Ref: ODVA CIP Vol. 1, Appendix A, Common Services (section unverified). Stop.
pub const SERVICE_STOP: USINT = 0x07;
// Ref: ODVA CIP Vol. 1, Appendix A, Common Services (section unverified). Create.
pub const SERVICE_CREATE: USINT = 0x08;
// Ref: ODVA CIP Vol. 1, Appendix A, Common Services (section unverified). Delete.
pub const SERVICE_DELETE: USINT = 0x09;
// Ref: ODVA CIP Vol. 1, Appendix A, Common Services (section unverified). Multiple_Service_Packet.
pub const SERVICE_MULTIPLE_SERVICE_PACKET: USINT = 0x0A;
// Ref: ODVA CIP Vol. 1, Appendix A, Common Services (section unverified). Apply_Attributes.
pub const SERVICE_APPLY_ATTRIBUTES: USINT = 0x0D;
// Ref: ODVA CIP Vol. 1, Appendix A, Common Services (section unverified). Get_Attribute_Single.
pub const SERVICE_GET_ATTRIBUTE_SINGLE: USINT = 0x0E;
// Ref: ODVA CIP Vol. 1, Appendix A, Common Services (section unverified). Set_Attribute_Single.
pub const SERVICE_SET_ATTRIBUTE_SINGLE: USINT = 0x10;
// Ref: ODVA CIP Vol. 1, Appendix A, Common Services (section unverified). Find_Next_Object_Instance.
pub const SERVICE_FIND_NEXT_OBJECT_INSTANCE: USINT = 0x11;
// Ref: ODVA CIP Vol. 1, Appendix A, Common Services (section unverified). Restore.
pub const SERVICE_RESTORE: USINT = 0x15;
// Ref: ODVA CIP Vol. 1, Appendix A, Common Services (section unverified). Save.
pub const SERVICE_SAVE: USINT = 0x16;
// Ref: ODVA CIP Vol. 1, Appendix A, Common Services (section unverified). Nop.
pub const SERVICE_NOP: USINT = 0x17;
// Ref: ODVA CIP Vol. 1, Appendix A, Common Services (section unverified). Get_Member.
pub const SERVICE_GET_MEMBER: USINT = 0x18;
// Ref: ODVA CIP Vol. 1, Appendix A, Common Services (section unverified). Set_Member.
pub const SERVICE_SET_MEMBER: USINT = 0x19;
// Ref: ODVA CIP Vol. 1, Appendix A, Common Services (section unverified). Insert_Member.
pub const SERVICE_INSERT_MEMBER: USINT = 0x1A;
// Ref: ODVA CIP Vol. 1, Appendix A, Common Services (section unverified). Remove_Member.
pub const SERVICE_REMOVE_MEMBER: USINT = 0x1B;
// Ref: ODVA CIP Vol. 1, Appendix A, Common Services (section unverified). Group_Sync.
pub const SERVICE_GROUP_SYNC: USINT = 0x1C;

// ---------------------------------------------------------------------------
// Class IDs
// ---------------------------------------------------------------------------

// Ref: ODVA CIP Vol. 1, Chapter 5 "Object Library" - Identity Object, class code 0x01
// (section unverified).
pub const CLASS_IDENTITY: UINT = 0x01;
// Ref: ODVA CIP Vol. 1, Object Library - Message Router Object, class code 0x02 (section unverified).
pub const CLASS_MESSAGE_ROUTER: UINT = 0x02;
// Ref: ODVA CIP Vol. 3 (DeviceNet) - DeviceNet Object, class code 0x03 (section unverified).
pub const CLASS_DEVICENET: UINT = 0x03;
// Ref: ODVA CIP Vol. 1, Object Library - Assembly Object, class code 0x04 (section unverified).
pub const CLASS_ASSEMBLY: UINT = 0x04;
// Ref: ODVA CIP Vol. 1, Object Library - Connection Object, class code 0x05 (section unverified).
pub const CLASS_CONNECTION: UINT = 0x05;
// Ref: ODVA CIP Vol. 1, Object Library - Connection Manager Object, class code 0x06 (section unverified).
pub const CLASS_CONNECTION_MGR: UINT = 0x06;
// Ref: ODVA CIP Vol. 1, Object Library - Register Object, class code 0x07 (section unverified).
pub const CLASS_REGISTER: UINT = 0x07;
// Ref: ODVA CIP Vol. 1, Object Library - Parameter Object, class code 0x0F (section unverified).
pub const CLASS_PARAMETER: UINT = 0x0F;
// Ref: ODVA CIP Vol. 1, Object Library - Parameter Group Object, class code 0x10 (section unverified).
pub const CLASS_PARAMETER_GROUP: UINT = 0x10;
// Ref: ODVA CIP Vol. 1, Object Library - Group Object, class code 0x12 (section unverified).
pub const CLASS_GROUP: UINT = 0x12;
// Ref: ODVA CIP Vol. 1, Object Library - Discrete Input Point Object, class code 0x08 (section unverified). Deviation from Go, which used 0x1D.
pub const CLASS_DISCRETE_INPUT: UINT = 0x08;
// Ref: ODVA CIP Vol. 1, Object Library - Discrete Output Point Object, class code 0x09 (section unverified). Deviation from Go, which used 0x1E.
pub const CLASS_DISCRETE_OUTPUT: UINT = 0x09;
// Ref: ODVA CIP Vol. 1, Object Library - Analog Input Point Object, class code 0x0A (section unverified). Deviation from Go, which used 0x1F.
pub const CLASS_ANALOG_INPUT: UINT = 0x0A;
// Ref: ODVA CIP Vol. 1, Object Library - Analog Output Point Object, class code 0x0B (section unverified). Deviation from Go, which used 0x20.
pub const CLASS_ANALOG_OUTPUT: UINT = 0x0B;
// Ref: ODVA CIP Vol. 1, Object Library - Position Sensor Object, class code 0x23 (section unverified).
pub const CLASS_POSITION_SENSOR: UINT = 0x23;
// Ref: ODVA CIP Vol. 1, Object Library - Position Controller Object, class code 0x25 (section unverified). Deviation from Go, which used 0x24 (Position Controller Supervisor).
pub const CLASS_POSITION_CTRL: UINT = 0x25;
// Ref: ODVA CIP Vol. 1, Object Library - AC/DC Drive Object, class code 0x2A (section unverified).
pub const CLASS_AC_DRIVE: UINT = 0x2A;
// Ref: ODVA CIP Vol. 1, Object Library - Overload Object, class code 0x2C (section unverified); Motor Data is class 0x28.
pub const CLASS_MOTOR_OVERLOAD: UINT = 0x2C;
// Ref: ODVA CIP Vol. 5 (CIP on ControlNet) - ControlNet Object, class code 0xF0 (section unverified).
pub const CLASS_CONTROL_NET: UINT = 0xF0;
// Ref: ODVA EtherNet/IP Adaptation of CIP (CIP Vol. 2), Ethernet Link Object, class code 0xF6
// (section unverified).
pub const CLASS_ETHERNET_LINK: UINT = 0xF6;
// Ref: ODVA EtherNet/IP Adaptation of CIP (CIP Vol. 2), TCP/IP Interface Object, class code 0xF5
// (section unverified).
pub const CLASS_TCPIP_INTERFACE: UINT = 0xF5;

// Ref: Allen-Bradley PCCC Object (class 0x67), Rockwell/Allen-Bradley PCCC / DF1 protocol manual
// 1770-6.5.16 and CIP vendor-specific object space (section unverified). PCCC commands are
// tunnelled to legacy SLC/MicroLogix/PLC-5 controllers via this object using the Execute_PCCC
// service ([`crate::cip::services::SERVICE_EXECUTE_PCCC`]).
pub const CLASS_PCCC: UINT = 0x67;

// ---------------------------------------------------------------------------
// DataType
// ---------------------------------------------------------------------------

// Ref: ODVA CIP Vol. 1, Appendix C "Data Management" - data type reporting / elementary data
// type codes (section unverified). NOTE: treating bit 15 (0x8000) as an "array flag" is a
// convention inherited from the Go library, NOT the Rockwell Symbol Object layout. In the
// Symbol Object type word (Rockwell 1756-PM020 Logix 5000 Data Access, attribute 2, section
// unverified) bit 15 marks a structure/UDT and bits 13-14 give the array dimension count.
// It is kept here because the custom-type registry uses codes (e.g. 0x2F83) that overlap the
// dimension bits.
// DataType is a CIP data type code (16-bit). By library convention bit 15 is the array flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct DataType(pub u16);

// Ref: ODVA CIP Vol. 1, Appendix C "Data Management" - elementary data type codes (section
// unverified); appear as the first two bytes of a Logix Read Tag response
// (Rockwell 1756-PM020 Logix 5000 Data Access). BOOL.
pub const TYPE_BOOL: DataType = DataType(0x00C1);
// Ref: CIP Vol. 1, Appendix C data type codes (section unverified). SINT.
pub const TYPE_SINT: DataType = DataType(0x00C2);
// Ref: CIP Vol. 1, Appendix C data type codes (section unverified). INT.
pub const TYPE_INT: DataType = DataType(0x00C3);
// Ref: CIP Vol. 1, Appendix C data type codes (section unverified). DINT.
pub const TYPE_DINT: DataType = DataType(0x00C4);
// Ref: CIP Vol. 1, Appendix C data type codes (section unverified). LINT.
pub const TYPE_LINT: DataType = DataType(0x00C5);
// Ref: CIP Vol. 1, Appendix C data type codes (section unverified). USINT.
pub const TYPE_USINT: DataType = DataType(0x00C6);
// Ref: CIP Vol. 1, Appendix C data type codes (section unverified). UINT.
pub const TYPE_UINT: DataType = DataType(0x00C7);
// Ref: CIP Vol. 1, Appendix C data type codes (section unverified). UDINT.
pub const TYPE_UDINT: DataType = DataType(0x00C8);
// Ref: CIP Vol. 1, Appendix C data type codes (section unverified). ULINT.
pub const TYPE_ULINT: DataType = DataType(0x00C9);
// Ref: CIP Vol. 1, Appendix C data type codes (section unverified). REAL.
pub const TYPE_REAL: DataType = DataType(0x00CA);
// Ref: CIP Vol. 1, Appendix C data type codes (section unverified). LREAL.
pub const TYPE_LREAL: DataType = DataType(0x00CB);
// Ref: CIP Vol. 1, Appendix C data type codes (section unverified). STIME.
pub const TYPE_STIME: DataType = DataType(0x00CC);
// Ref: CIP Vol. 1, Appendix C data type codes (section unverified). DATE.
pub const TYPE_DATE: DataType = DataType(0x00CD);
// Ref: CIP Vol. 1, Appendix C data type codes (section unverified). TIME_OF_DAY.
pub const TYPE_TIME_OF_DAY: DataType = DataType(0x00CE);
// Ref: CIP Vol. 1, Appendix C data type codes (section unverified). DATE_AND_TIME.
pub const TYPE_DATE_AND_TIME: DataType = DataType(0x00CF);
// Ref: CIP Vol. 1, Appendix C data type codes (section unverified). STRING.
pub const TYPE_STRING: DataType = DataType(0x00D0);
// Ref: CIP Vol. 1, Appendix C data type codes (section unverified). BYTE.
pub const TYPE_BYTE: DataType = DataType(0x00D1);
// Ref: CIP Vol. 1, Appendix C data type codes (section unverified). WORD.
pub const TYPE_WORD: DataType = DataType(0x00D2);
// Ref: CIP Vol. 1, Appendix C data type codes (section unverified). DWORD.
pub const TYPE_DWORD: DataType = DataType(0x00D3);
// Ref: CIP Vol. 1, Appendix C data type codes (section unverified). LWORD.
pub const TYPE_LWORD: DataType = DataType(0x00D4);
// Ref: CIP Vol. 1, Appendix C data type codes (section unverified). STRING2.
pub const TYPE_STRING2: DataType = DataType(0x00D5);
// Ref: CIP Vol. 1, Appendix C data type codes (section unverified). FTIME.
pub const TYPE_FTIME: DataType = DataType(0x00D6);
// Ref: CIP Vol. 1, Appendix C data type codes (section unverified). LTIME.
pub const TYPE_LTIME: DataType = DataType(0x00D7);
// Ref: CIP Vol. 1, Appendix C data type codes (section unverified). ITIME.
pub const TYPE_ITIME: DataType = DataType(0x00D8);
// Ref: CIP Vol. 1, Appendix C data type codes (section unverified). STRINGN.
pub const TYPE_STRINGN: DataType = DataType(0x00D9);
// Ref: CIP Vol. 1, Appendix C data type codes (section unverified). SHORT_STRING.
pub const TYPE_SHORT_STRING: DataType = DataType(0x00DA);
// Ref: CIP Vol. 1, Appendix C data type codes (section unverified). TIME.
pub const TYPE_TIME: DataType = DataType(0x00DB);
// Ref: CIP Vol. 1, Appendix C data type codes (section unverified). EPATH.
pub const TYPE_EPATH: DataType = DataType(0x00DC);
// Ref: CIP Vol. 1, Appendix C data type codes (section unverified). ENGUNIT.
pub const TYPE_ENGUNIT: DataType = DataType(0x00DD);
// Ref: CIP Vol. 1, Appendix C data type codes (section unverified). STRINGI.
pub const TYPE_STRINGI: DataType = DataType(0x00DE);
// Ref: Rockwell 1756-PM020 Logix 5000 Data Access - structure tag type marker (0x02A0 is the
// common struct type code used by Logix; the code is followed by a 2-byte structure handle on
// the wire). Not an ODVA-defined elementary type.
pub const TYPE_STRUCT: DataType = DataType(0x02A0);

// ---------------------------------------------------------------------------
// General status codes
// ---------------------------------------------------------------------------

// Ref: ODVA CIP Vol. 1, Appendix B "Status Codes" - Table B-1.1 General Status Codes (table
// number from memory, unverified). Success.
pub const STATUS_SUCCESS: USINT = 0x00;
// Ref: CIP Vol. 1, Appendix B General Status Codes: 0x05 Path destination unknown.
pub const STATUS_PATH_DESTINATION_UNKNOWN: USINT = 0x05;
// Ref: CIP Vol. 1, Appendix B General Status Codes: 0x06 Partial transfer.
pub const STATUS_PARTIAL_TRANSFER: USINT = 0x06;
// Ref: CIP Vol. 1, Appendix B General Status Codes: 0x1E Embedded service error (a service inside
// a Multiple_Service_Packet failed; the embedded replies are still present).
pub const STATUS_EMBEDDED_SERVICE_ERROR: USINT = 0x1E;
// Ref: CIP Vol. 1, Appendix B General Status Codes: 0x1C is "Missing attribute list entry data"
// (the Go source names it AttributeListShortage).
pub const STATUS_ATTRIBUTE_LIST_SHORTAGE: USINT = 0x1C;
// Ref: CIP Vol. 1, Appendix B General Status Codes: 0x04 Path segment error.
pub const STATUS_PATH_SEGMENT_ERROR: USINT = 0x04;
// Ref: CIP Vol. 1, Appendix B General Status Codes: 0x01 Connection failure.
pub const STATUS_CONNECTION_FAILURE: USINT = 0x01;
// Ref: CIP Vol. 1, Appendix B General Status Codes: 0x02 Resource unavailable.
pub const STATUS_RESOURCE_UNAVAILABLE: USINT = 0x02;
// Ref: CIP Vol. 1, Appendix B General Status Codes: 0x03 Invalid parameter value (section
// unverified). The Go source called this "InvalidSegmentType".
pub const STATUS_INVALID_PARAMETER_VALUE: USINT = 0x03;
// Ref: CIP Vol. 1, Appendix B General Status Codes: 0x08 Service not supported.
pub const STATUS_SERVICE_NOT_SUPPORTED: USINT = 0x08;
// Ref: CIP Vol. 1, Appendix B General Status Codes: 0x09 Invalid attribute value.
pub const STATUS_INVALID_ATTRIBUTE_VALUE: USINT = 0x09;
// Ref: CIP Vol. 1, Appendix B General Status Codes: 0x0E Attribute not settable.
pub const STATUS_ATTRIBUTE_NOT_SETTABLE: USINT = 0x0E;
// Ref: CIP Vol. 1, Appendix B General Status Codes: 0x0F Privilege violation (permission denied).
// Deviation from Go: the Go constants block used 0x10 here (off by one); corrected to the spec.
pub const STATUS_PRIVILEGE_VIOLATION: USINT = 0x0F;
// Ref: CIP Vol. 1, Appendix B General Status Codes: 0x10 Device state conflict.
// Deviation from Go: Go used 0x11; corrected to the spec.
pub const STATUS_DEVICE_STATE_CONFLICT: USINT = 0x10;
// Ref: CIP Vol. 1, Appendix B General Status Codes: 0x11 Reply data too large.
// Deviation from Go: Go used 0x12 (Fragmentation primitive error in the spec); corrected.
pub const STATUS_REPLY_DATA_TOO_LARGE: USINT = 0x11;
// Ref: CIP Vol. 1, Appendix B General Status Codes: 0x13 Not enough data.
pub const STATUS_NOT_ENOUGH_DATA: USINT = 0x13;
// Ref: CIP Vol. 1, Appendix B General Status Codes: 0x14 Attribute not supported.
pub const STATUS_ATTRIBUTE_NOT_SUPPORTED: USINT = 0x14;
// Ref: CIP Vol. 1, Appendix B General Status Codes: 0x15 Too much data.
pub const STATUS_TOO_MUCH_DATA: USINT = 0x15;
// Ref: CIP Vol. 1, Appendix B General Status Codes: 0x16 Object does not exist.
pub const STATUS_OBJECT_DOES_NOT_EXIST: USINT = 0x16;
// Ref: CIP Vol. 1, Appendix B General Status Codes: 0x17 Service fragmentation sequence not in
// progress (section unverified). Go used 0x2D, which is not a defined general status.
pub const STATUS_SERVICE_FRAGMENTATION: USINT = 0x17;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

// Ref: ODVA CIP Vol. 1, Chapter 2/3 Message Router response format: General Status followed by
// Additional Status Size and Additional Status words (section unverified).
// Error is a CIP-level error holding a general status code and optional extended status words
// (Go `cip.Error`).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Error {
    pub status: USINT,
    pub ext_status: Vec<UINT>,
}

impl Error {
    // Implementation detail (convenience constructor, not spec).
    // Creates an Error with only a general status.
    pub fn new(status: USINT) -> Error {
        Error { status, ext_status: Vec::new() }
    }

    // Implementation detail (convenience constructor, not spec).
    // Creates an Error with general status and extended status words.
    pub fn with_ext(status: USINT, ext_status: Vec<UINT>) -> Error {
        Error { status, ext_status }
    }
}

// Implementation detail: formatting matches the Go `Error()` method
// ("CIP Error: Status=0x%02X ExtStatus=%04X").
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.ext_status.is_empty() {
            // Go prints a []UINT with %04X as "[0100 0200]".
            let words: Vec<String> = self.ext_status.iter().map(|w| format!("{:04X}", w)).collect();
            write!(f, "CIP Error: Status=0x{:02X} ExtStatus=[{}]", self.status, words.join(" "))
        } else {
            write!(f, "CIP Error: Status=0x{:02X}", self.status)
        }
    }
}

impl std::error::Error for Error {}

// Implementation detail (crate error plumbing, not spec): the error type for every fallible
// operation in the cip layer. Go returns plain `error` values here; the variants preserve the
// kinds/messages (io.EOF, io.ErrUnexpectedEOF, `cip.Error`, fmt.Errorf messages).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CipError {
    // A CIP general-status error (Go `cip.Error`).
    Status(Error),
    // Go `io.EOF`: no data left at all when a read began.
    Eof,
    // Go `io.ErrUnexpectedEOF`: input ended part-way through a value.
    UnexpectedEof,
    // Go "insufficient data for <kind>: expected at least N bytes, got M".
    InsufficientData { kind: &'static str, expected: usize, got: usize },
    // Go "cip: binary.Read failed: %w" wrapping the underlying read error.
    BinaryRead(Box<CipError>),
    // Go tag-path syntax errors ("cip: ..." messages from ParseTagPath).
    TagPath(String),
    // Any other message error.
    Other(String),
}

impl fmt::Display for CipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CipError::Status(e) => write!(f, "{}", e),
            CipError::Eof => write!(f, "EOF"),
            CipError::UnexpectedEof => write!(f, "unexpected EOF"),
            CipError::InsufficientData { kind, expected, got } => write!(
                f,
                "insufficient data for {}: expected at least {} bytes, got {}",
                kind, expected, got
            ),
            CipError::BinaryRead(inner) => write!(f, "cip: binary.Read failed: {}", inner),
            CipError::TagPath(s) => write!(f, "{}", s),
            CipError::Other(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for CipError {}

impl From<Error> for CipError {
    fn from(e: Error) -> CipError {
        CipError::Status(e)
    }
}

// Implementation detail: per-layer Result alias.
pub type Result<T> = std::result::Result<T, CipError>;

// ---------------------------------------------------------------------------
// DataType helpers
// ---------------------------------------------------------------------------

impl DataType {
    // Ref: Rockwell 1756-PM020 Logix 5000 Data Access, Symbol Object Type attribute (section
    // unverified). Bit 15 (0x8000) of the symbol type word marks a structure; the low 12 bits are
    // then the template instance ID.
    pub fn is_struct(self) -> bool {
        (self.0 & 0x8000) != 0
    }

    // Ref: Rockwell 1756-PM020 Logix 5000 Data Access, Symbol Object Type attribute (section
    // unverified). Bits 13-14 hold the array dimension count (0..=3).
    pub fn array_dims(self) -> u8 {
        ((self.0 >> 13) & 0x3) as u8
    }

    // Ref: Rockwell 1756-PM020 Logix 5000 Data Access, Symbol Object Type attribute (section
    // unverified). True if at least one array dimension is encoded (bits 13-14 non-zero).
    // Deviation from Go, which treated bit 15 as the array flag.
    pub fn is_array(self) -> bool {
        self.array_dims() != 0
    }

    // Ref: Rockwell 1756-PM020 Logix 5000 Data Access, Symbol Object Type attribute (section
    // unverified). Low 12 bits: atomic type code or structure template instance ID.
    pub fn template_instance(self) -> u16 {
        self.0 & 0x0FFF
    }

    // Ref: Rockwell 1756-PM020 Logix 5000 Data Access, Symbol Object Type attribute (section
    // unverified). Returns the type code with the structure flag and array dimension bits
    // cleared (the system bit 12 and low 12 bits are kept). Used as the registry key.
    pub fn base(self) -> DataType {
        DataType(self.0 & 0x1FFF)
    }
}

// Ref: ODVA CIP Vol. 1, Appendix C data type codes (section unverified); names follow the CIP
// elementary type names.
// Built-in name table for the data type codes.
fn type_name(dt: DataType) -> Option<&'static str> {
    Some(match dt {
        TYPE_BOOL => "BOOL",
        TYPE_SINT => "SINT",
        TYPE_INT => "INT",
        TYPE_DINT => "DINT",
        TYPE_LINT => "LINT",
        TYPE_USINT => "USINT",
        TYPE_UINT => "UINT",
        TYPE_UDINT => "UDINT",
        TYPE_ULINT => "ULINT",
        TYPE_REAL => "REAL",
        TYPE_LREAL => "LREAL",
        TYPE_STIME => "STIME",
        TYPE_DATE => "DATE",
        TYPE_TIME_OF_DAY => "TIME_OF_DAY",
        TYPE_DATE_AND_TIME => "DATE_AND_TIME",
        TYPE_STRING => "STRING",
        TYPE_BYTE => "BYTE",
        TYPE_WORD => "WORD",
        TYPE_DWORD => "DWORD",
        TYPE_LWORD => "LWORD",
        TYPE_STRING2 => "STRING2",
        TYPE_FTIME => "FTIME",
        TYPE_LTIME => "LTIME",
        TYPE_ITIME => "ITIME",
        TYPE_STRINGN => "STRINGN",
        TYPE_SHORT_STRING => "SHORT_STRING",
        TYPE_TIME => "TIME",
        TYPE_EPATH => "EPATH",
        TYPE_ENGUNIT => "ENGUNIT",
        TYPE_STRINGI => "STRINGI",
        TYPE_STRUCT => "STRUCT",
        _ => return None,
    })
}

// Returns a human-readable name for the data type (e.g. "DINT", "REAL[]"). If the code is not a
// built-in CIP type the custom type registry is consulted (see `registry::register_type`).
// Ref: ODVA CIP Vol. 1, Appendix C data type codes (section unverified).
impl fmt::Display for DataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let base = self.base();
        // Structure-flagged codes name a template, never an atomic type.
        let atomic = if self.is_struct() { None } else { type_name(base) };
        let name: String = match atomic {
            Some(n) => n.to_string(),
            None => crate::cip::registry::lookup_type_name(base),
        };
        if name.is_empty() {
            if self.is_array() {
                return write!(f, "UNKNOWN(0x{:04X})[]", base.0);
            }
            return write!(f, "UNKNOWN(0x{:04X})", self.0);
        }
        if self.is_array() {
            return write!(f, "{}[]", name);
        }
        write!(f, "{}", name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== DataType String and Flag Helpers =====

    // Ref: Go TestDataTypeString - CIP Vol. 1, Appendix C data type codes (section unverified).
    #[test]
    fn data_type_string() {
        let tests: Vec<(DataType, &str)> = vec![
            (TYPE_BOOL, "BOOL"),
            (TYPE_DINT, "DINT"),
            (TYPE_REAL, "REAL"),
            (TYPE_STRING, "STRING"),
            (TYPE_STRUCT, "STRUCT"),
            (DataType(0x20C4), "DINT[]"), // Array dimension bits set
            (DataType(0x00FF), "UNKNOWN(0x00FF)"),
        ];
        for (dt, want) in tests {
            assert_eq!(dt.to_string(), want, "DataType(0x{:04X})", dt.0);
        }
    }

    // Ref: Go TestDataTypeIsArray - Rockwell 1756-PM020 symbol type word (array dims in bits
    // 13-14, structure flag bit 15; section unverified). Deviation from Go (bit 15 as array).
    #[test]
    fn data_type_is_array() {
        assert!(!TYPE_DINT.is_array(), "TypeDINT should not be array");
        let arr = DataType(0x20C4);
        assert!(arr.is_array(), "0x20C4 should be array");
        assert_eq!(arr.base(), TYPE_DINT);
        assert_eq!(DataType(0x6000 | 0xC4).array_dims(), 3);
        let st = DataType(0x8123);
        assert!(st.is_struct() && !st.is_array());
        assert_eq!(st.template_instance(), 0x0123);
        assert_eq!(st.to_string(), "UNKNOWN(0x8123)");
    }

    // Ref: CIP Vol. 1, Appendix B General Status Codes (0x0F, 0x10, 0x11).
    #[test]
    fn status_code_values() {
        assert_eq!(STATUS_PRIVILEGE_VIOLATION, 0x0F);
        assert_eq!(STATUS_DEVICE_STATE_CONFLICT, 0x10);
        assert_eq!(STATUS_REPLY_DATA_TOO_LARGE, 0x11);
        assert_eq!(STATUS_EMBEDDED_SERVICE_ERROR, 0x1E);
    }

    // Ref: Go TestStatusCodesExist - CIP Vol. 1, Appendix B General Status Codes.
    #[test]
    fn status_codes_exist() {
        let codes: Vec<(&str, USINT)> = vec![
            ("Success", STATUS_SUCCESS),
            ("ConnectionFailure", STATUS_CONNECTION_FAILURE),
            ("ResourceUnavailable", STATUS_RESOURCE_UNAVAILABLE),
            ("PathSegmentError", STATUS_PATH_SEGMENT_ERROR),
            ("PathDestUnknown", STATUS_PATH_DESTINATION_UNKNOWN),
            ("PartialTransfer", STATUS_PARTIAL_TRANSFER),
            ("ServiceNotSupported", STATUS_SERVICE_NOT_SUPPORTED),
            ("InvalidAttributeVal", STATUS_INVALID_ATTRIBUTE_VALUE),
            ("AttributeNotSettable", STATUS_ATTRIBUTE_NOT_SETTABLE),
            ("PrivilegeViolation", STATUS_PRIVILEGE_VIOLATION),
            ("DeviceStateConflict", STATUS_DEVICE_STATE_CONFLICT),
            ("ReplyDataTooLarge", STATUS_REPLY_DATA_TOO_LARGE),
            ("NotEnoughData", STATUS_NOT_ENOUGH_DATA),
            ("AttrNotSupported", STATUS_ATTRIBUTE_NOT_SUPPORTED),
            ("TooMuchData", STATUS_TOO_MUCH_DATA),
            ("ObjectDoesNotExist", STATUS_OBJECT_DOES_NOT_EXIST),
        ];
        for (name, code) in codes {
            if code == 0 && name != "Success" {
                panic!("status code {} is zero (likely undefined)", name);
            }
        }
    }

    // Ref: Go TestCIPErrorString - Error formatting (implementation detail).
    #[test]
    fn cip_error_string() {
        let e = Error::new(STATUS_OBJECT_DOES_NOT_EXIST);
        assert!(!e.to_string().is_empty(), "error string should not be empty");
        assert_eq!(e.to_string(), "CIP Error: Status=0x16");

        let e2 = Error::with_ext(STATUS_CONNECTION_FAILURE, vec![0x0100]);
        assert!(!e2.to_string().is_empty(), "error string with ext status should not be empty");
        assert_eq!(e2.to_string(), "CIP Error: Status=0x01 ExtStatus=[0100]");
    }

    // Ref: Go TestCIPServiceCodes - CIP Vol. 1 Appendix A common services; Rockwell 1756-PM020.
    #[test]
    fn cip_service_codes() {
        use crate::cip::services::*;
        assert_eq!(SERVICE_GET_ATTRIBUTE_ALL, 0x01);
        assert_eq!(SERVICE_READ_TAG, 0x4C);
        assert_eq!(SERVICE_WRITE_TAG, 0x4D);
        assert_eq!(SERVICE_READ_TAG_FRAGMENTED, 0x52);
        assert_eq!(SERVICE_WRITE_TAG_FRAGMENTED, 0x53);
        // Note: ServiceForwardOpen (0x54) is defined in the connmgr package, not cip
    }

    // Ref: Go TestCIPClassIDs - CIP Vol. 1 Object Library class codes.
    #[test]
    fn cip_class_ids() {
        assert_eq!(CLASS_IDENTITY, 0x01);
        assert_eq!(CLASS_CONNECTION_MGR, 0x06);
    }

    // Ref: Go TestCIPDataTypeCodes - CIP Vol. 1 Appendix C data type codes.
    #[test]
    fn cip_data_type_codes() {
        assert_eq!(TYPE_BOOL.0, 0x00C1);
        assert_eq!(TYPE_SINT.0, 0x00C2);
        assert_eq!(TYPE_INT.0, 0x00C3);
        assert_eq!(TYPE_DINT.0, 0x00C4);
        assert_eq!(TYPE_LINT.0, 0x00C5);
        assert_eq!(TYPE_USINT.0, 0x00C6);
        assert_eq!(TYPE_UINT.0, 0x00C7);
        assert_eq!(TYPE_UDINT.0, 0x00C8);
        assert_eq!(TYPE_ULINT.0, 0x00C9);
        assert_eq!(TYPE_REAL.0, 0x00CA);
        assert_eq!(TYPE_LREAL.0, 0x00CB);
        assert_eq!(TYPE_STRING.0, 0x00D0);
    }
}
