//! Logix-style tag name to EPATH parsing.
//!
//! Port of Go `cip/tag.go`.

use super::path::*;
use super::types::*;

// Ref: Rockwell 1756-PM020 Logix 5000 Data Access - symbolic tag addressing: tag names become
// ANSI Extended Symbol segments (CIP Vol. 1, Appendix C Data Segment, section unverified), array
// indices and bit numbers become Member ID logical segments (CIP Vol. 1, Appendix C logical
// segment).
// Converts a Logix-style tag string into a CIP EPATH composed of ANSI Extended Symbol segments
// and (where applicable) Member ID segments for array indices and BOOL bit access.
//
// Supported syntax:
//
//   "MyTag"                              simple controller-scoped tag
//   "MyStruct.Field"                     struct member access
//   "MyArray[5]"                         1D array element
//   "Matrix[2,3]"                        2D array element
//   "Cube[1,2,3]"                        3D array element
//   "Program:MainProgram.MyTag"          program-scoped tag
//   "Program:Foo.Bar[5].Baz"             program scope + array + member
//   "Local:2:I.Data[0]"                  module I/O tag with array element
//   "MyDINT.5"                           bit access on an integer (BOOL bit 5)
//
// Only "." and "[...]" act as segment separators. Colons remain inside the symbol because they
// appear in program-scope prefixes ("Program:Name") and module I/O tag names ("Local:2:I"). A
// purely numeric token after "." is encoded as a Member ID segment (used for BOOL bit access);
// a token containing any non-digit character is encoded as a symbol. Array indices inside
// "[...]" are always encoded as Member ID segments.
//
// On invalid syntax an error is returned.
pub fn parse_tag_path(tag: &str) -> Result<Path> {
    if tag.is_empty() {
        return Err(CipError::TagPath("cip: empty tag path".to_string()));
    }

    let parts = split_tag_segments(tag)?;

    let mut p = Path::new();
    for (i, part) in parts.iter().enumerate() {
        let (name, indices) = parse_tag_segment(part)
            .map_err(|e| CipError::TagPath(format!("cip: tag {:?}: {}", tag, e)))?;
        if name.is_empty() && indices.is_empty() {
            return Err(CipError::TagPath(format!("cip: tag {:?}: empty segment", tag)));
        }
        if !name.is_empty() {
            if i > 0 && is_all_digits(name) {
                // Bit access on a previous symbol, e.g. "MyDINT.5" -> Member(5).
                match parse_u32(name) {
                    Some(n) => add_member32(&mut p, n),
                    None => {
                        return Err(CipError::TagPath(format!(
                            "cip: tag {:?}: invalid numeric member {:?}",
                            tag, name
                        )));
                    }
                }
            } else {
                p.add_symbolic_segment(name)?;
            }
        }
        for idx in indices {
            add_member32(&mut p, idx);
        }
    }
    Ok(p)
}

// Implementation detail (string parsing helper, not spec): splits a tag path on '.' while
// keeping '[...]' groups intact. Returns one entry per dotted segment; bracket groups stay
// attached to the preceding symbol (e.g. "Foo[1].Bar" -> ["Foo[1]", "Bar"]).
fn split_tag_segments(tag: &str) -> Result<Vec<&str>> {
    let mut parts: Vec<&str> = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    for (i, &c) in tag.as_bytes().iter().enumerate() {
        match c {
            b'[' => depth += 1,
            b']' => {
                if depth == 0 {
                    return Err(CipError::TagPath(format!("cip: tag {:?}: unmatched ']'", tag)));
                }
                depth -= 1;
            }
            b'.'
                if depth == 0 => {
                    parts.push(&tag[start..i]);
                    start = i + 1;
                }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(CipError::TagPath(format!("cip: tag {:?}: unmatched '['", tag)));
    }
    parts.push(&tag[start..]);
    Ok(parts)
}

// Implementation detail (string parsing helper, not spec): splits "Name[i,j,...]" into its name
// and a list of indices. A bare "Name" returns name + no indices. A bare "[i]" (no name) is
// allowed only as a follow-on segment but is uncommon; it returns name="" + indices. Error
// strings are returned bare (the caller adds the tag prefix), like Go.
fn parse_tag_segment(seg: &str) -> std::result::Result<(&str, Vec<u32>), String> {
    let open = match seg.find('[') {
        Some(o) => o,
        None => return Ok((seg, Vec::new())),
    };
    let name = &seg[..open];
    if !seg.ends_with(']') {
        return Err(format!("segment {:?}: bracket group not closed", seg));
    }
    // `open < seg.len()` and seg ends with ']', so open+1 <= len-1 unless seg == "[" which is
    // impossible after split_tag_segments; use checked slicing regardless.
    let inner = match seg.get(open + 1..seg.len() - 1) {
        Some(s) => s,
        None => return Err(format!("segment {:?}: bracket group not closed", seg)),
    };
    if inner.is_empty() {
        return Err(format!("segment {:?}: empty index", seg));
    }
    let mut indices = Vec::new();
    for part in inner.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err(format!("segment {:?}: empty index value", seg));
        }
        match parse_u32(part) {
            Some(n) => indices.push(n),
            None => return Err(format!("segment {:?}: invalid index {:?}", seg, part)),
        }
    }
    Ok((name, indices))
}

// Implementation detail: Go `isAllDigits` (ASCII digits, non-empty).
fn is_all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

// Implementation detail: Go `strconv.ParseUint(s, 10, 32)` - digits only (no sign), must fit u32.
fn parse_u32(s: &str) -> Option<u32> {
    if !is_all_digits(s) {
        return None;
    }
    s.parse::<u32>().ok()
}

// Ref: CIP Vol. 1, Appendix C logical segment - Member ID with 8/16/32-bit formats (section
// unverified); Rockwell 1756-PM020 Logix 5000 Data Access: this is the encoding Logix
// controllers expect for array indices and BOOL bit access.
// Appends a Member ID segment, choosing 8-, 16-, or 32-bit encoding by the value's magnitude.
fn add_member32(p: &mut Path, id: u32) {
    if id <= 0xFF {
        p.0.push(SEGMENT_TYPE_LOGICAL | LOGICAL_TYPE_MEMBER | LOGICAL_FORMAT_8BIT);
        p.0.push(id as u8);
    } else if id <= 0xFFFF {
        p.0.push(SEGMENT_TYPE_LOGICAL | LOGICAL_TYPE_MEMBER | LOGICAL_FORMAT_16BIT);
        p.0.push(0x00);
        p.0.extend_from_slice(&(id as u16).to_le_bytes());
    } else {
        p.0.push(SEGMENT_TYPE_LOGICAL | LOGICAL_TYPE_MEMBER | LOGICAL_FORMAT_32BIT);
        p.0.push(0x00);
        p.0.extend_from_slice(&id.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Hex helper: uppercase hex of the path bytes.
    fn hex(p: &Path) -> String {
        p.bytes().iter().map(|b| format!("{:02X}", b)).collect()
    }

    // Ref: Rockwell 1756-PM020 Logix 5000 Data Access symbolic tag addressing; CIP Vol. 1,
    // Appendix C ANSI Extended Symbol + Member logical segments.
    // Each `want` value is the expected EPATH byte sequence as a hex string. Whitespace inside
    // `want` is stripped before comparison so the byte groupings stay legible.
    #[test]
    fn parse_tag_path_cases() {
        let tests: Vec<(&str, &str, String)> = vec![
            (
                "simple symbol",
                "MyTag",
                // symbol("MyTag", 5 chars, pad)
                "9105 4D79546167 00".to_string(),
            ),
            (
                "struct member",
                "MyStruct.Field",
                // symbol("MyStruct", 8 chars, no pad) + symbol("Field", 5 chars, pad)
                "9108 4D79537472756374 9105 4669656C64 00".to_string(),
            ),
            (
                "program scope + member + array + member",
                "Program:MainProgram.MyArray[5].Field",
                "9113 50726F6772616D3A4D61696E50726F6772616D 00".to_string()
                    + "9107 4D7941727261 79 00"
                    + "28 05"
                    + "9105 4669656C64 00",
            ),
            (
                "2D array index",
                "Matrix[2,3]",
                // symbol("Matrix", 6 chars, no pad) + member(2) + member(3)
                "9106 4D6174726978 2802 2803".to_string(),
            ),
            (
                "bit access on integer",
                "MyDINT.5",
                // symbol("MyDINT", 6 chars, no pad) + member(5)
                "9106 4D7944494E54 2805".to_string(),
            ),
            (
                "16-bit array index",
                "BigArray[300]",
                // symbol("BigArray", 8 chars, no pad) + member16(300=0x012C)
                "9108 4269674172726179 29 00 2C01".to_string(),
            ),
            (
                "module I/O tag with colons and array",
                "Local:2:I.Data[0]",
                // symbol("Local:2:I", 9 chars, pad) + symbol("Data", 4 chars, no pad) + member(0)
                "9109 4C6F63616C3A323A49 00 9104 44617461 2800".to_string(),
            ),
            (
                "user case",
                "Program:MainProgram.Tote_Count_CNTR.ACC",
                "9113 50726F6772616D3A4D61696E50726F6772616D 00".to_string()
                    + "910F 546F74655F436F756E745F434E5452 00"
                    + "9103 414343 00",
            ),
        ];

        for (name, tag, want) in tests {
            let p = parse_tag_path(tag).unwrap_or_else(|e| panic!("{}: ParseTagPath({:?}): {}", name, tag, e));
            let got = hex(&p);
            let want_hex = want.replace(' ', "").to_uppercase();
            assert_eq!(got, want_hex, "{}: ParseTagPath({:?})", name, tag);
        }
    }

    // Ref: same as above - invalid tag syntax is rejected.
    #[test]
    fn parse_tag_path_errors() {
        let cases = [
            "",         // empty
            "Foo[",     // unmatched [
            "Foo]",     // unmatched ]
            "Foo[]",    // empty brackets
            "Foo[abc]", // non-numeric index
            "Foo[1,]",  // empty index value
            "Foo..Bar", // empty middle segment
            "Foo.",     // empty trailing segment
            ".Foo",     // empty leading segment
        ];
        for c in cases {
            assert!(parse_tag_path(c).is_err(), "ParseTagPath({:?}): expected error, got Ok", c);
        }
    }

    // Added: error message shapes and 32-bit/odd inputs (Go messages preserved).
    #[test]
    fn parse_tag_path_messages_and_edges() {
        assert_eq!(parse_tag_path("").unwrap_err().to_string(), "cip: empty tag path");
        assert_eq!(parse_tag_path("Foo]").unwrap_err().to_string(), "cip: tag \"Foo]\": unmatched ']'");
        assert_eq!(parse_tag_path("Foo[").unwrap_err().to_string(), "cip: tag \"Foo[\": unmatched '['");
        assert_eq!(
            parse_tag_path("Foo[abc]").unwrap_err().to_string(),
            "cip: tag \"Foo[abc]\": segment \"Foo[abc]\": invalid index \"abc\""
        );
        assert_eq!(parse_tag_path("Foo.").unwrap_err().to_string(), "cip: tag \"Foo.\": empty segment");
        // 32-bit index
        let p = parse_tag_path("A[70000]").unwrap();
        assert_eq!(p.bytes(), &[0x91, 0x01, b'A', 0x00, 0x2A, 0x00, 0x70, 0x11, 0x01, 0x00]);
        // Index with whitespace is trimmed; sign is rejected.
        assert!(parse_tag_path("A[ 1 , 2 ]").is_ok());
        assert!(parse_tag_path("A[+1]").is_err());
        // Numeric first token is a symbol, not a member.
        assert_eq!(parse_tag_path("5").unwrap().bytes(), &[0x91, 0x01, b'5', 0x00]);
        // Non-ASCII input never panics.
        let _ = parse_tag_path("Ünï[1].é");
        let _ = parse_tag_path("é[");
    }
}
