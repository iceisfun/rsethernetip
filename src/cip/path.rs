//! EPATH (Encoded Path) construction.
//!
//! Port of Go `cip/path.go`.

use std::fmt;

use super::types::*;

// Ref: ODVA CIP Vol. 1, Appendix C "Data Management" - Segment Types (bits 7-5 of the segment
// byte select the segment type; section unverified).
// Port segment (000xxxxx).
pub const SEGMENT_TYPE_PORT: u8 = 0x00;
// Ref: CIP Vol. 1, Appendix C segment types (section unverified). Logical segment (001xxxxx).
pub const SEGMENT_TYPE_LOGICAL: u8 = 0x20;
// Ref: CIP Vol. 1, Appendix C segment types (section unverified). Network segment (010xxxxx).
pub const SEGMENT_TYPE_NETWORK: u8 = 0x40;
// Ref: CIP Vol. 1, Appendix C segment types (section unverified). Symbolic segment (011xxxxx).
pub const SEGMENT_TYPE_SYMBOLIC: u8 = 0x60;
// Ref: CIP Vol. 1, Appendix C segment types (section unverified). Data segment (100xxxxx).
pub const SEGMENT_TYPE_DATA: u8 = 0x80;
// Ref: CIP Vol. 1, Appendix C segment types (section unverified). Data type segment, constructed (101xxxxx).
pub const SEGMENT_TYPE_DATA_TYPE1: u8 = 0xA0;
// Ref: CIP Vol. 1, Appendix C segment types (section unverified). Data type segment, elementary (110xxxxx).
pub const SEGMENT_TYPE_DATA_TYPE2: u8 = 0xC0;
// Ref: CIP Vol. 1, Appendix C segment types (section unverified). Reserved (111xxxxx).
pub const SEGMENT_TYPE_RESERVED: u8 = 0xE0;

// Ref: ODVA CIP Vol. 1, Appendix C "Data Management" - Logical Segment, logical type (bits 4-2;
// section unverified). Class ID.
pub const LOGICAL_TYPE_CLASS: u8 = 0x00;
// Ref: CIP Vol. 1, Appendix C logical segment, logical type (section unverified). Instance ID.
pub const LOGICAL_TYPE_INSTANCE: u8 = 0x04;
// Ref: CIP Vol. 1, Appendix C logical segment, logical type (section unverified). Member ID.
pub const LOGICAL_TYPE_MEMBER: u8 = 0x08;
// Ref: CIP Vol. 1, Appendix C logical segment, logical type (section unverified). Connection Point.
pub const LOGICAL_TYPE_POINT: u8 = 0x0C;
// Ref: CIP Vol. 1, Appendix C logical segment, logical type (section unverified). Attribute ID.
pub const LOGICAL_TYPE_ATTRIBUTE: u8 = 0x10;
// Ref: CIP Vol. 1, Appendix C logical segment, logical type (section unverified). Special.
pub const LOGICAL_TYPE_SPECIAL: u8 = 0x14;
// Ref: CIP Vol. 1, Appendix C logical segment, logical type (section unverified). Service ID.
pub const LOGICAL_TYPE_SERVICE: u8 = 0x18;
// Ref: CIP Vol. 1, Appendix C logical segment, logical type (section unverified). Extended Logical.
pub const LOGICAL_TYPE_EXTENDED: u8 = 0x1C;

// Ref: ODVA CIP Vol. 1, Appendix C "Data Management" - Logical Segment, logical format (bits
// 1-0: 8-, 16- or 32-bit value; section unverified). 8-bit.
pub const LOGICAL_FORMAT_8BIT: u8 = 0x00;
// Ref: CIP Vol. 1, Appendix C logical segment, logical format (section unverified). 16-bit (followed by a pad byte).
pub const LOGICAL_FORMAT_16BIT: u8 = 0x01;
// Ref: CIP Vol. 1, Appendix C logical segment, logical format (section unverified). 32-bit (followed by a pad byte).
pub const LOGICAL_FORMAT_32BIT: u8 = 0x02;
// Ref: CIP Vol. 1, Appendix C logical segment, logical format (section unverified). Reserved.
pub const LOGICAL_FORMAT_RESERVED: u8 = 0x03;

// Ref: ODVA CIP Vol. 1, Appendix C "Data Management" - EPATH (Encoded Path) segment sequence
// (section unverified). A variable-length byte sequence of typed segments addressing CIP
// objects by class, instance, attribute, connection point or symbolic tag name.
#[derive(Clone, Debug, PartialEq, Eq, Default, Hash)]
pub struct Path(pub Vec<u8>);

impl From<Vec<u8>> for Path {
    fn from(v: Vec<u8>) -> Path {
        Path(v)
    }
}

impl From<&[u8]> for Path {
    fn from(v: &[u8]) -> Path {
        Path(v.to_vec())
    }
}

// Appends a 16-bit (padded) logical segment of the given logical type. Shared by the Add* helpers.
// Ref: CIP Vol. 1, Appendix C logical segment 16-bit format: [seg][pad][lo][hi] (section unverified).
fn push_logical16(p: &mut Vec<u8>, ltype: u8, v: u16) {
    p.push(SEGMENT_TYPE_LOGICAL | ltype | LOGICAL_FORMAT_16BIT);
    p.push(0x00); // Pad
    p.extend_from_slice(&v.to_le_bytes());
}

impl Path {
    // Creates a new empty EPATH. Use the add_* methods to append segments.
    // Ref: CIP Vol. 1, Appendix C EPATH (section unverified).
    pub fn new() -> Path {
        Path(Vec::new())
    }

    // Ref: CIP Vol. 1, Appendix C logical segment - Class ID (section unverified). Values up to
    // 0xFF use the compact 8-bit format; larger values use the 16-bit format.
    pub fn add_class(&mut self, class_id: UINT) {
        if class_id <= 0xFF {
            self.0.push(SEGMENT_TYPE_LOGICAL | LOGICAL_TYPE_CLASS | LOGICAL_FORMAT_8BIT);
            self.0.push(class_id as u8);
        } else {
            push_logical16(&mut self.0, LOGICAL_TYPE_CLASS, class_id);
        }
    }

    // Ref: CIP Vol. 1, Appendix C logical segment - Instance ID (section unverified).
    pub fn add_instance(&mut self, instance_id: UINT) {
        if instance_id <= 0xFF {
            self.0.push(SEGMENT_TYPE_LOGICAL | LOGICAL_TYPE_INSTANCE | LOGICAL_FORMAT_8BIT);
            self.0.push(instance_id as u8);
        } else {
            push_logical16(&mut self.0, LOGICAL_TYPE_INSTANCE, instance_id);
        }
    }

    // Ref: CIP Vol. 1, Appendix C logical segment - Instance ID with 8/16/32-bit formats
    // (section unverified). Automatically chooses the encoding based on the value.
    pub fn add_instance32(&mut self, instance_id: u32) {
        if instance_id <= 0xFF {
            self.0.push(SEGMENT_TYPE_LOGICAL | LOGICAL_TYPE_INSTANCE | LOGICAL_FORMAT_8BIT);
            self.0.push(instance_id as u8);
        } else if instance_id <= 0xFFFF {
            push_logical16(&mut self.0, LOGICAL_TYPE_INSTANCE, instance_id as u16);
        } else {
            self.0.push(SEGMENT_TYPE_LOGICAL | LOGICAL_TYPE_INSTANCE | LOGICAL_FORMAT_32BIT);
            self.0.push(0x00); // Pad
            self.0.extend_from_slice(&instance_id.to_le_bytes());
        }
    }

    // Ref: CIP Vol. 1, Appendix C logical segment - Attribute ID (section unverified).
    pub fn add_attribute(&mut self, attribute_id: UINT) {
        if attribute_id <= 0xFF {
            self.0.push(SEGMENT_TYPE_LOGICAL | LOGICAL_TYPE_ATTRIBUTE | LOGICAL_FORMAT_8BIT);
            self.0.push(attribute_id as u8);
        } else {
            push_logical16(&mut self.0, LOGICAL_TYPE_ATTRIBUTE, attribute_id);
        }
    }

    // Ref: CIP Vol. 1, Appendix C logical segment - Connection Point (0x2C/0x2D; section
    // unverified). Connection points identify assembly instances in Forward_Open requests.
    pub fn add_connection_point(&mut self, point_id: UINT) {
        if point_id <= 0xFF {
            self.0.push(SEGMENT_TYPE_LOGICAL | LOGICAL_TYPE_POINT | LOGICAL_FORMAT_8BIT);
            self.0.push(point_id as u8);
        } else {
            push_logical16(&mut self.0, LOGICAL_TYPE_POINT, point_id);
        }
    }

    // Ref: CIP Vol. 1, Appendix C logical segment - Member ID (section unverified).
    pub fn add_member(&mut self, member_id: UINT) {
        if member_id <= 0xFF {
            self.0.push(SEGMENT_TYPE_LOGICAL | LOGICAL_TYPE_MEMBER | LOGICAL_FORMAT_8BIT);
            self.0.push(member_id as u8);
        } else {
            push_logical16(&mut self.0, LOGICAL_TYPE_MEMBER, member_id);
        }
    }

    // Ref: CIP Vol. 1, Appendix C Data Segment - ANSI Extended Symbol segment (0x91; section
    // unverified); Rockwell 1756-PM020 Logix 5000 Data Access uses it to address tags by name.
    // The segment is padded to a 16-bit word boundary.
    //
    // Deviation from Go: a symbol longer than 255 bytes (one-byte length field) is rejected
    // instead of silently truncating the length; the path is left unchanged on error.
    pub fn add_symbolic_segment(&mut self, symbol: &str) -> Result<()> {
        let l = symbol.len();
        if l > 0xFF {
            return Err(CipError::Other(format!(
                "cip: symbolic segment of {} bytes exceeds 255",
                l
            )));
        }
        self.0.push(0x91); // Extended Symbol Segment (Data Segment 0x80 | 0x11)
        self.0.push(l as u8);
        self.0.extend_from_slice(symbol.as_bytes());
        if !l.is_multiple_of(2) {
            self.0.push(0x00); // Pad to even length
        }
        Ok(())
    }

    // Ref: CIP Vol. 1, Appendix C Port Segment (port identifier + link address; extended port
    // number and extended link address size forms; section unverified). Used to route CIP
    // messages through a backplane or network port to a downstream device.
    // Field order: [segment byte][link address size (if extended)][extended port UINT (if port
    // nibble is 0x0F)][link address][pad].
    //
    // Deviation from Go: the Go order wrote the port before the link-address size, and a link
    // address over 255 bytes was truncated; the order is fixed and oversize addresses rejected
    // (path unchanged on error).
    pub fn add_port_segment(&mut self, port: UINT, link_address: &[u8]) -> Result<()> {
        if link_address.len() > 0xFF {
            return Err(CipError::Other(format!(
                "cip: port link address of {} bytes exceeds 255",
                link_address.len()
            )));
        }
        let seg_start = self.0.len();

        let mut b: u8;
        if port < 15 {
            b = SEGMENT_TYPE_PORT | (port as u8);
        } else {
            // Extended port: set port nibble to 0x0F
            b = SEGMENT_TYPE_PORT | 0x0F;
        }

        if link_address.len() > 1 {
            b |= 0x10; // Extended link address bit
        }

        self.0.push(b);

        if link_address.len() > 1 {
            // Write link address length byte (precedes the extended port number)
            self.0.push(link_address.len() as u8);
        }

        if port >= 15 {
            // Write the actual port number as a uint16
            self.0.extend_from_slice(&port.to_le_bytes());
        }

        self.0.extend_from_slice(link_address);

        // Pad to 16-bit word boundary if the segment length is odd
        if !(self.0.len() - seg_start).is_multiple_of(2) {
            self.0.push(0x00);
        }
        Ok(())
    }

    // Returns the raw encoded path bytes.
    // Ref: CIP Vol. 1, Appendix C EPATH (section unverified).
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }

    // Implementation detail: byte length of the encoded path.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    // Implementation detail: true if the path has no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    // Ref: CIP Vol. 1, Message Router request format - Request_Path_Size is in 16-bit words
    // (section unverified). Returns the path length in 16-bit words (truncated to a byte);
    // use `try_len_words` to reject paths over 510 bytes.
    pub fn len_words(&self) -> u8 {
        self.0.len().div_ceil(2) as u8
    }

    // Ref: CIP Vol. 1, Message Router request format - Request_Path_Size is a USINT count of
    // 16-bit words (section unverified). Errors if the path exceeds 255 words (510 bytes).
    // Deviation from Go, which truncated silently.
    pub fn try_len_words(&self) -> Result<u8> {
        let w = self.0.len().div_ceil(2);
        u8::try_from(w).map_err(|_| {
            CipError::Other(format!("cip: path of {} bytes exceeds 510 bytes", self.0.len()))
        })
    }
}

// Implementation detail: hex-encoded representation (uppercase) as in Go `Path.String`.
impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{:02X}", b)?;
        }
        Ok(())
    }
}

// Ref: CIP Vol. 1, Appendix C logical segments - standard Class/Instance/Attribute path
// (section unverified). If `attribute_id` is 0 the attribute segment is omitted.
pub fn build_path(class_id: UINT, instance_id: UINT, attribute_id: UINT) -> Path {
    let mut p = Path::new();
    p.add_class(class_id);
    p.add_instance(instance_id);
    if attribute_id != 0 {
        p.add_attribute(attribute_id);
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== EPATH Segment Type Identification (from OpENer cipepathtest.cpp) =====
    // Ref: CIP Vol. 1, Appendix C segment types (section unverified).
    #[test]
    fn segment_type_from_byte() {
        let tests: Vec<(&str, u8, u8)> = vec![
            ("PortSegment", 0x00, SEGMENT_TYPE_PORT),
            ("PortSegment_0x0F", 0x0F, SEGMENT_TYPE_PORT),
            ("LogicalSegment", 0x20, SEGMENT_TYPE_LOGICAL),
            ("LogicalSegment_0x3F", 0x3F, SEGMENT_TYPE_LOGICAL),
            ("NetworkSegment", 0x40, SEGMENT_TYPE_NETWORK),
            ("NetworkSegment_0x5F", 0x5F, SEGMENT_TYPE_NETWORK),
            ("SymbolicSegment", 0x60, SEGMENT_TYPE_SYMBOLIC),
            ("SymbolicSegment_0x7F", 0x7F, SEGMENT_TYPE_SYMBOLIC),
            ("DataSegment", 0x80, SEGMENT_TYPE_DATA),
            ("DataSegment_ANSI", 0x91, SEGMENT_TYPE_DATA),
            ("DataTypeConstructed", 0xA0, SEGMENT_TYPE_DATA_TYPE1),
            ("DataTypeElementary", 0xC0, SEGMENT_TYPE_DATA_TYPE2),
            ("Reserved", 0xE0, SEGMENT_TYPE_RESERVED),
        ];
        for (name, raw, want) in tests {
            let got = raw & 0xE0; // Top 3 bits determine segment type
            assert_eq!(got, want, "{}: segment type byte 0x{:02X}", name, raw);
        }
    }

    // ===== Logical Segment Type Identification =====
    // Ref: CIP Vol. 1, Appendix C logical segment type field (section unverified).
    #[test]
    fn logical_segment_type() {
        let tests: Vec<(&str, u8, u8)> = vec![
            ("ClassID", 0x20, LOGICAL_TYPE_CLASS),
            ("InstanceID", 0x24, LOGICAL_TYPE_INSTANCE),
            ("MemberID", 0x28, LOGICAL_TYPE_MEMBER),
            ("ConnectionPoint", 0x2C, LOGICAL_TYPE_POINT),
            ("AttributeID", 0x30, LOGICAL_TYPE_ATTRIBUTE),
            ("Special", 0x34, LOGICAL_TYPE_SPECIAL),
            ("ServiceID", 0x38, LOGICAL_TYPE_SERVICE),
            ("ExtendedLogical", 0x3C, LOGICAL_TYPE_EXTENDED),
        ];
        for (name, raw, want_lt) in tests {
            let got = (raw >> 2) & 0x07; // Bits 4-2 of the segment byte
            let want = (want_lt >> 2) & 0x07;
            assert_eq!(got, want, "{}: logical type from 0x{:02X}", name, raw);
        }
    }

    // ===== Logical Segment Format Identification =====
    // Ref: CIP Vol. 1, Appendix C logical segment format field (section unverified).
    #[test]
    fn logical_segment_format() {
        let tests: Vec<(&str, u8, u8)> = vec![
            ("8Bit", 0x20, LOGICAL_FORMAT_8BIT),
            ("16Bit", 0x21, LOGICAL_FORMAT_16BIT),
            ("32Bit", 0x22, LOGICAL_FORMAT_32BIT),
            ("Reserved", 0x23, LOGICAL_FORMAT_RESERVED),
        ];
        for (name, raw, format) in tests {
            let got = raw & 0x03; // Bottom 2 bits
            assert_eq!(got, format, "{}: format from 0x{:02X}", name, raw);
        }
    }

    // ===== EPATH Building - known-good patterns from OpENer =====

    // Ref: CIP Vol. 1, Appendix C logical class segment.
    #[test]
    fn path_build_8bit_class() {
        let mut p = Path::new();
        p.add_class(0x04);
        assert_eq!(p.bytes(), &[0x20, 0x04]);
    }

    #[test]
    fn path_build_16bit_class() {
        let mut p = Path::new();
        p.add_class(0x0100);
        assert_eq!(p.bytes(), &[0x21, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn path_build_8bit_instance() {
        let mut p = Path::new();
        p.add_instance(0x01);
        assert_eq!(p.bytes(), &[0x24, 0x01]);
    }

    #[test]
    fn path_build_16bit_instance() {
        let mut p = Path::new();
        p.add_instance(0x0200);
        assert_eq!(p.bytes(), &[0x25, 0x00, 0x00, 0x02]);
    }

    #[test]
    fn path_build_32bit_instance() {
        let mut p = Path::new();
        p.add_instance32(0x00010000);
        assert_eq!(p.bytes(), &[0x26, 0x00, 0x00, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn path_build_8bit_attribute() {
        let mut p = Path::new();
        p.add_attribute(0x03);
        assert_eq!(p.bytes(), &[0x30, 0x03]);
    }

    #[test]
    fn path_build_16bit_attribute() {
        let mut p = Path::new();
        p.add_attribute(0x0300);
        assert_eq!(p.bytes(), &[0x31, 0x00, 0x00, 0x03]);
    }

    #[test]
    fn path_build_8bit_member() {
        let mut p = Path::new();
        p.add_member(0x05);
        assert_eq!(p.bytes(), &[0x28, 0x05]);
    }

    #[test]
    fn path_build_16bit_member() {
        let mut p = Path::new();
        p.add_member(0x0400);
        assert_eq!(p.bytes(), &[0x29, 0x00, 0x00, 0x04]);
    }

    // Ref: CIP Vol. 1, Appendix C ANSI Extended Symbol segment.
    #[test]
    fn path_build_symbolic_even_length() {
        let mut p = Path::new();
        p.add_symbolic_segment("Test").unwrap();
        assert_eq!(p.bytes(), &[0x91, 0x04, b'T', b'e', b's', b't']);
    }

    #[test]
    fn path_build_symbolic_odd_pad() {
        let mut p = Path::new();
        p.add_symbolic_segment("Tag").unwrap();
        assert_eq!(p.bytes(), &[0x91, 0x03, b'T', b'a', b'g', 0x00]);
    }

    // Ref: CIP Vol. 1, Appendix C port segment.
    #[test]
    fn path_build_port_segment_simple() {
        let mut p = Path::new();
        p.add_port_segment(1, &[0x00]).unwrap(); // Port 1, link address 0
        assert_eq!(p.bytes(), &[0x01, 0x00]);
    }

    // Ref: CIP Vol. 1, Appendix C port segment, extended port + extended link address
    // (section unverified): size byte precedes the port UINT.
    #[test]
    fn path_build_port_segment_extended_port_and_link() {
        let mut p = Path::new();
        p.add_port_segment(0x0102, &[0xAA, 0xBB, 0xCC]).unwrap();
        assert_eq!(p.bytes(), &[0x1F, 0x03, 0x02, 0x01, 0xAA, 0xBB, 0xCC, 0x00]);
    }

    #[test]
    fn path_length_limits() {
        let mut p = Path::new();
        assert!(p.add_symbolic_segment(&"a".repeat(256)).is_err());
        assert!(p.add_port_segment(1, &[0u8; 256]).is_err());
        assert!(p.is_empty());
        p.add_symbolic_segment(&"a".repeat(255)).unwrap();
        assert!(p.try_len_words().is_ok());
        let big = Path(vec![0u8; 512]);
        assert!(big.try_len_words().is_err());
    }

    #[test]
    fn path_build_port_segment_extended() {
        let mut p = Path::new();
        p.add_port_segment(15, &[0x01]).unwrap(); // Extended port number
        // Port >= 15: uses 0x0F with extended port bytes
        assert!(p.bytes().len() >= 4, "extended port segment too short: {} bytes", p.bytes().len());
        assert_eq!(p.bytes(), &[0x0F, 0x0F, 0x00, 0x01]);
        // First byte should have port nibble = 0x0F
        assert_eq!(p.bytes()[0] & 0x0F, 0x0F);
    }

    #[test]
    fn path_build_complex() {
        // Build Class 4, Instance 1, Attribute 3 - standard CIP path
        let p = build_path(0x04, 0x01, 0x03);
        let expect = [
            0x20, 0x04, // Class 4
            0x24, 0x01, // Instance 1
            0x30, 0x03, // Attribute 3
        ];
        assert_eq!(p.bytes(), &expect);
        assert_eq!(p.len_words(), 3);
    }

    #[test]
    fn path_build_no_attribute() {
        // Attribute 0 means "no attribute segment"
        let p = build_path(0x04, 0x01, 0);
        assert_eq!(p.bytes(), &[0x20, 0x04, 0x24, 0x01]);
    }

    // ===== Data Segment Subtype Identification =====
    // Ref: CIP Vol. 1, Appendix C data segment subtypes: 0x80 simple data, 0x91 ANSI Extended Symbol.
    #[test]
    fn data_segment_subtype() {
        let tests: Vec<(&str, u8, u8)> = vec![
            ("SimpleData", 0x80, 0x00),
            ("ANSIExtendedSymbol", 0x91, 0x11),
            ("Reserved", 0x81, 0x01),
        ];
        for (name, raw, subtype) in tests {
            let got = raw & 0x1F; // Bottom 5 bits for data segment subtype
            assert_eq!(got, subtype, "{}: data segment subtype from 0x{:02X}", name, raw);
        }
    }

    // ===== Network Segment Subtype Identification =====
    // Ref: CIP Vol. 1, Appendix C network segment subtypes (section unverified).
    // From OpENer: Schedule=0x41, FixedTag=0x42, ProdInhibitMs=0x43, Safety=0x44
    #[test]
    fn network_segment_subtype() {
        const NET_SUB_SCHEDULE: u8 = 0x01;
        const NET_SUB_FIXED_TAG: u8 = 0x02;
        const NET_SUB_PROD_INHIBIT_MS: u8 = 0x03;
        const NET_SUB_SAFETY: u8 = 0x04;
        const NET_SUB_PROD_INHIBIT_US: u8 = 0x10;
        const NET_SUB_EXTENDED_NETWORK: u8 = 0x1F;
        let tests: Vec<(&str, u8, u8)> = vec![
            ("Schedule", 0x41, NET_SUB_SCHEDULE),
            ("FixedTag", 0x42, NET_SUB_FIXED_TAG),
            ("ProdInhibitMs", 0x43, NET_SUB_PROD_INHIBIT_MS),
            ("Safety", 0x44, NET_SUB_SAFETY),
            ("ProdInhibitUs", 0x50, NET_SUB_PROD_INHIBIT_US),
            ("ExtendedNetwork", 0x5F, NET_SUB_EXTENDED_NETWORK),
        ];
        for (name, raw, subtype) in tests {
            let got = raw & 0x1F;
            assert_eq!(got, subtype, "{}: network segment subtype from 0x{:02X}", name, raw);
        }
    }

    // ===== Tests mined from cpppo =====

    // extpath_3: class/instance/attribute 8- and 16-bit forms.
    // Ref: CIP Vol. 1, Appendix C logical segments.
    #[test]
    fn path_mixed_segments() {
        let mut p = Path::new();
        p.add_class(0x11);
        assert_eq!(p.bytes(), &[0x20, 0x11]);

        let mut p = Path::new();
        p.add_class(0x0211);
        assert_eq!(p.bytes(), &[0x21, 0x00, 0x11, 0x02]);

        let mut p = Path::new();
        p.add_instance(0x21);
        assert_eq!(p.bytes(), &[0x24, 0x21]);

        let mut p = Path::new();
        p.add_instance(0x0221);
        assert_eq!(p.bytes(), &[0x25, 0x00, 0x21, 0x02]);

        let mut p = Path::new();
        p.add_attribute(0x31);
        assert_eq!(p.bytes(), &[0x30, 0x31]);

        let mut p = Path::new();
        p.add_attribute(0x0231);
        assert_eq!(p.bytes(), &[0x31, 0x00, 0x31, 0x02]);
    }

    // extpath_4: symbolic segments.
    #[test]
    fn path_symbolic_segments() {
        let mut p = Path::new();
        p.add_symbolic_segment("abc123").unwrap();
        assert_eq!(p.bytes(), &[0x91, 0x06, b'a', b'b', b'c', b'1', b'2', b'3']);

        let mut p = Path::new();
        p.add_symbolic_segment("xyz12").unwrap();
        assert_eq!(p.bytes(), &[0x91, 0x05, b'x', b'y', b'z', b'1', b'2', 0x00]);
    }

    // extpath_9: Assembly class 0x04, instance 5.
    #[test]
    fn path_assembly_class_instance() {
        let mut p = Path::new();
        p.add_class(0x04);
        p.add_instance(0x05);
        assert_eq!(p.bytes(), &[0x20, 0x04, 0x24, 0x05]);
    }

    // extpath_5: port #1, link 0x00.
    #[test]
    fn path_port_segment_basic() {
        let mut p = Path::new();
        p.add_port_segment(1, &[0x00]).unwrap();
        assert_eq!(p.bytes(), &[0x01, 0x00]);
    }

    #[test]
    fn path_len_words() {
        // cpppo extpath_0: 0 words (empty path)
        let p = Path::new();
        assert_eq!(p.len_words(), 0);

        // cpppo extpath_1: 1 word (2 bytes)
        let mut p = Path::new();
        p.add_member(0x01);
        assert_eq!(p.len_words(), 1);

        // cpppo extpath_4: 8 words (16 bytes for two symbolic segments)
        let mut p = Path::new();
        p.add_symbolic_segment("abc123").unwrap();
        p.add_symbolic_segment("xyz12").unwrap();
        assert_eq!(p.len_words(), 8);
    }

    // cpppo gaa_008_request CIP path: class 0x66, instance 1.
    #[test]
    fn path_build_get_attribute_all_path() {
        let p = build_path(0x66, 0x01, 0);
        assert_eq!(p.bytes(), &[0x20, 0x66, 0x24, 0x01]);
    }

    // cpppo gaa_011_request: Identity Object, instance 1.
    #[test]
    fn path_build_identity_object_path() {
        let p = build_path(0x01, 0x01, 0);
        assert_eq!(p.bytes(), &[0x20, 0x01, 0x24, 0x01]);
    }

    // cpppo Unconnected Send path: Connection Manager, instance 1.
    #[test]
    fn path_build_connection_manager_path() {
        let p = build_path(0x06, 0x01, 0);
        assert_eq!(p.bytes(), &[0x20, 0x06, 0x24, 0x01]);
    }

    // Display is uppercase hex (Go Path.String).
    #[test]
    fn path_display_hex() {
        let p = Path(vec![0x20, 0x04, 0xAB]);
        assert_eq!(p.to_string(), "2004AB");
    }
}
