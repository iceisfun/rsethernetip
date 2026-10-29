//! Symbol Object (class 0x6B) helpers for tag enumeration on Logix controllers.
//!
//! Port of Go `cip/symbol.go`.

use super::message::MessageRouterRequest;
use super::path::Path;
use super::types::*;

// Ref: Rockwell 1756-PM020 Logix 5000 Data Access - Symbol Object, class code 0x6B, used to
// enumerate tags on Logix controllers.
pub const CLASS_SYMBOL: UINT = 0x6B;

// Ref: Rockwell 1756-PM020 Logix 5000 Data Access - Symbol Object instance attributes (name,
// type). A single tag entry discovered by enumerating the Symbol Object class: instance ID,
// tag name and CIP data type code.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SymbolInstance {
    pub instance_id: u32,
    pub name: String,
    pub type_: DataType,
}

// Ref: Rockwell 1756-PM020 Logix 5000 Data Access - Get_Instance_Attribute_List service (0x55).
pub const SERVICE_GET_INSTANCE_ATTRIBUTE_LIST: USINT = 0x55;

// Implementation detail: little-endian cursor over a byte slice mirroring binary.Read /
// io.ReadFull semantics (EOF when nothing left, unexpected EOF on a partial value).
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let rest = &self.data[self.pos..];
        if rest.is_empty() && n > 0 {
            return Err(CipError::Eof);
        }
        if rest.len() < n {
            return Err(CipError::UnexpectedEof);
        }
        self.pos += n;
        Ok(&rest[..n])
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
}

// Ref: Rockwell 1756-PM020 Logix 5000 Data Access - Symbol Object class attributes 1 (revision)
// and 2 (maximum instance); CIP Vol. 1 Get_Attribute_List (service 0x03; Appendix A common
// services, section unverified).
// Creates a Get_Attribute_List request targeting the Symbol Class object (instance 0) to
// retrieve the class revision and maximum instance ID.
pub fn new_get_symbol_class_attributes_request() -> MessageRouterRequest {
    let mut p = Path::new();
    p.add_class(CLASS_SYMBOL);
    p.add_instance(0);

    let mut buf = Vec::with_capacity(6);
    buf.extend_from_slice(&2u16.to_le_bytes()); // 2 Attributes
    buf.extend_from_slice(&1u16.to_le_bytes()); // Attr 1: Revision
    buf.extend_from_slice(&2u16.to_le_bytes()); // Attr 2: Max Instance

    MessageRouterRequest {
        service: SERVICE_GET_ATTRIBUTE_LIST, // GetAttributeList
        request_path: p,
        request_data: buf,
    }
}

// Ref: CIP Vol. 1 Get_Attribute_List reply format (count, then per attribute: ID, status,
// value; section unverified); Rockwell 1756-PM020 Symbol Object class attributes.
// Decodes the Get_Attribute_List response from the Symbol Class (0x6B, instance 0) and returns
// (revision, max_instance). Go behavior retained: attributes other than 1 and 2 with status 0
// are not skipped (no value is consumed).
pub fn decode_symbol_class_attributes_response(data: &[u8]) -> Result<(u16, u16)> {
    let mut r = Reader::new(data);
    let count = r.u16()?;

    let mut revision = 0u16;
    let mut max_instance = 0u16;

    for _ in 0..count {
        let attr_id = r.u16()?;
        let status = r.u16()?;

        if status == 0 {
            match attr_id {
                1 => {
                    // Revision (UINT)
                    revision = r.u16()?;
                }
                2 => {
                    // Max Instance (UINT)
                    max_instance = r.u16()?;
                }
                _ => {}
            }
        }
    }
    Ok((revision, max_instance))
}

// Ref: Rockwell 1756-PM020 Logix 5000 Data Access - Symbol Object instance attributes 1 (name)
// and 2 (type); CIP Vol. 1 Get_Attribute_List (service 0x03).
// Creates a Get_Attribute_List request targeting a specific Symbol Object instance to retrieve
// its name and data type.
pub fn new_get_symbol_attributes_request(instance_id: u32) -> MessageRouterRequest {
    let mut p = Path::new();
    p.add_class(CLASS_SYMBOL);
    p.add_instance32(instance_id);

    let mut buf = Vec::with_capacity(6);
    buf.extend_from_slice(&2u16.to_le_bytes()); // 2 Attributes
    buf.extend_from_slice(&1u16.to_le_bytes()); // Attr 1: Name
    buf.extend_from_slice(&2u16.to_le_bytes()); // Attr 2: Type

    MessageRouterRequest {
        service: SERVICE_GET_ATTRIBUTE_LIST, // GetAttributeList
        request_path: p,
        request_data: buf,
    }
}

// Ref: CIP Vol. 1 Get_Attribute_List reply format (section unverified); Rockwell 1756-PM020
// Symbol Object instance attributes.
// Decodes the Get_Attribute_List response for a Symbol Object instance and returns
// (name, type code). The name bytes are converted lossily to UTF-8 (Go keeps raw bytes in a
// string).
pub fn decode_symbol_attributes_response(data: &[u8]) -> Result<(String, DataType)> {
    let mut r = Reader::new(data);
    let count = r.u16()?;

    let mut name = String::new();
    let mut type_code = 0u16;

    for _ in 0..count {
        let attr_id = r.u16()?;
        let status = r.u16()?;

        if status == 0 {
            match attr_id {
                1 => {
                    // Name (STRING): UINT length followed by that many bytes.
                    let name_len = r.u16()? as usize;
                    let name_bytes = r.take(name_len)?;
                    name = String::from_utf8_lossy(name_bytes).into_owned();
                }
                2 => {
                    // Type (UINT)
                    type_code = r.u16()?;
                }
                _ => {}
            }
        }
    }
    Ok((name, DataType(type_code)))
}

// Ref: Rockwell 1756-PM020 Logix 5000 Data Access - program-scoped tags live in a per-program
// symbol table, addressed by prefixing the Symbol Object path with the "Program:<name>"
// symbolic segment. Unlike the controller table it is not reachable through the plain 0x6B path.
// Returns `Get_Attribute_List` for the program's symbol class (instance 0).
pub fn new_get_symbol_class_attributes_request_in_program(program: &str) -> Result<MessageRouterRequest> {
    let mut req = new_get_symbol_class_attributes_request();
    req.request_path = program_symbol_path(program, 0)?;
    Ok(req)
}

// Same as [`new_get_symbol_attributes_request`] but for one instance of a program's symbol table.
pub fn new_get_symbol_attributes_request_in_program(program: &str, instance_id: u32) -> Result<MessageRouterRequest> {
    let mut req = new_get_symbol_attributes_request(instance_id);
    req.request_path = program_symbol_path(program, instance_id)?;
    Ok(req)
}

// [symbolic "Program:<name>"] [class 0x6B] [instance]
fn program_symbol_path(program: &str, instance_id: u32) -> Result<Path> {
    let mut p = Path::new();
    p.add_symbolic_segment(program)?;
    p.add_class(CLASS_SYMBOL);
    p.add_instance32(instance_id);
    Ok(p)
}

// Controller-scope symbols named "Program:<name>" are the programs themselves. Returns that name.
pub fn program_name(symbol_name: &str) -> Option<&str> {
    let name = symbol_name.strip_prefix("Program:")?;
    (!name.is_empty() && !name.contains('.')).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn program_class_attributes_request_prefixes_the_symbolic_segment() {
        let req = new_get_symbol_class_attributes_request_in_program("Program:Main").unwrap();
        let mut want = vec![0x91, 12];
        want.extend_from_slice(b"Program:Main");
        want.extend_from_slice(&[0x20, 0x6B, 0x24, 0x00]);
        assert_eq!(req.request_path.bytes(), want.as_slice());
        assert_eq!(req.service, 0x03);
        assert_eq!(req.request_data, vec![2, 0, 1, 0, 2, 0]);
    }

    #[test]
    fn program_attributes_request_pads_odd_names_and_uses_the_instance() {
        let req = new_get_symbol_attributes_request_in_program("Program:Mai", 0x0102).unwrap();
        let mut want = vec![0x91, 11];
        want.extend_from_slice(b"Program:Mai");
        want.push(0x00); // pad
        want.extend_from_slice(&[0x20, 0x6B, 0x25, 0x00, 0x02, 0x01]); // 16-bit instance
        assert_eq!(req.request_path.bytes(), want.as_slice());
        assert_eq!(req.request_data, vec![2, 0, 1, 0, 2, 0]);
    }

    #[test]
    fn program_names_are_recognised() {
        assert_eq!(program_name("Program:MainProgram"), Some("MainProgram"));
        assert_eq!(program_name("Program:"), None);
        assert_eq!(program_name("Pre_Diverter_PE_1"), None);
        assert_eq!(program_name("Program:Main.Tag"), None, "a member path is not a program");
    }

    // Ref: Rockwell 1756-PM020 Symbol Object class attributes (Go has no direct test; added).
    #[test]
    fn class_attributes_request_and_response() {
        let req = new_get_symbol_class_attributes_request();
        assert_eq!(req.service, 0x03);
        assert_eq!(req.request_path.bytes(), &[0x20, 0x6B, 0x24, 0x00]);
        assert_eq!(req.request_data, vec![2, 0, 1, 0, 2, 0]);

        // count=2: attr1 ok rev=0x0003, attr2 ok max=0x0140
        let resp = [2, 0, 1, 0, 0, 0, 3, 0, 2, 0, 0, 0, 0x40, 0x01];
        assert_eq!(decode_symbol_class_attributes_response(&resp).unwrap(), (3, 0x0140));
        // Failed attribute status leaves value zero and consumes nothing.
        let resp = [1, 0, 1, 0, 5, 0];
        assert_eq!(decode_symbol_class_attributes_response(&resp).unwrap(), (0, 0));
        // Truncation errors.
        assert_eq!(decode_symbol_class_attributes_response(&[]), Err(CipError::Eof));
        assert_eq!(decode_symbol_class_attributes_response(&[1]), Err(CipError::UnexpectedEof));
        assert_eq!(decode_symbol_class_attributes_response(&[1, 0, 1, 0, 0, 0]), Err(CipError::Eof));
    }

    // Ref: Rockwell 1756-PM020 Symbol Object instance attributes (Go has no direct test; added).
    #[test]
    fn instance_attributes_request_and_response() {
        let req = new_get_symbol_attributes_request(0x12345);
        assert_eq!(req.request_path.bytes(), &[0x20, 0x6B, 0x26, 0x00, 0x45, 0x23, 0x01, 0x00]);

        // name "Abc", type 0x00C4
        let resp = [2, 0, 1, 0, 0, 0, 3, 0, b'A', b'b', b'c', 2, 0, 0, 0, 0xC4, 0x00];
        let (name, ty) = decode_symbol_attributes_response(&resp).unwrap();
        assert_eq!(name, "Abc");
        assert_eq!(ty, TYPE_DINT);
        // Name length larger than the data is an error, never a panic.
        let bad = [1, 0, 1, 0, 0, 0, 0xFF, 0xFF, b'A'];
        assert_eq!(decode_symbol_attributes_response(&bad), Err(CipError::UnexpectedEof));
        let bad = [1, 0, 1, 0, 0, 0, 0xFF, 0xFF];
        assert_eq!(decode_symbol_attributes_response(&bad), Err(CipError::Eof));
    }
}
