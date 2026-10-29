//! ethernetip-server: a simple EtherNet/IP server that serves Logix-style tags. Port of Go
//! `examples/ethernetip/server`.
//!
//! The server accepts TCP connections, handles RegisterSession / UnRegisterSession / SendRRData,
//! and dispatches the CIP requests inside to a `MessageRouter`. A custom `TagObject` implements
//! Read Tag (0x4C), Write Tag (0x4D) and Get_Attribute_All (0x01) for a handful of tags, so any
//! EtherNet/IP client (including `ethernetip-read-tag`) can talk to it.
//!
//! Ref: CIP Vol. 2, Section 2-3 Encapsulation Message; Rockwell 1756-PM020 Logix 5000 Data
//! Access (Read/Write Tag); CIP Vol. 1, Appendix C EPATH - ANSI Extended Symbol segment (0x91).
//!
//! Usage:
//!   ethernetip-server -addr :44818

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use rsethernetip::cip::{
    self, CipError, DataType, MessageRouter, Object, Path, CLASS_ASSEMBLY, SERVICE_GET_ATTRIBUTE_ALL,
    SERVICE_READ_TAG, SERVICE_WRITE_TAG, TYPE_DINT, TYPE_REAL, TYPE_STRING,
};
use rsethernetip::cli::{self, Cli};
use rsethernetip::logging::{DefaultLogger, Level, Logger};
use rsethernetip::plc::Context;
use rsethernetip::server::Server;

// Implementation detail (not spec): one tag's stored type and raw little-endian value bytes.
struct TagEntry {
    data_type: DataType,
    data: Vec<u8>,
}

// Implementation detail (not spec): thread-safe in-memory tag table (Go `TagObject`).
struct TagObject {
    tags: RwLock<HashMap<String, TagEntry>>,
}

impl TagObject {
    fn new() -> TagObject {
        TagObject { tags: RwLock::new(HashMap::new()) }
    }

    fn set_tag(&self, name: &str, data_type: DataType, data: Vec<u8>) {
        self.tags.write().unwrap_or_else(|e| e.into_inner()).insert(name.to_string(), TagEntry { data_type, data });
    }

    // Ref: Rockwell 1756-PM020 Read Tag (0x4C): request data is the 2-byte element count; the
    // reply is the 2-byte CIP type code followed by the value bytes.
    fn handle_read_tag(&self, path: &Path, data: &[u8]) -> cip::Result<Vec<u8>> {
        let name = parse_symbolic_segment(path).map_err(|_| status(cip::STATUS_PATH_SEGMENT_ERROR))?;
        if data.len() < 2 {
            return Err(status(cip::STATUS_NOT_ENOUGH_DATA));
        }
        let tags = self.tags.read().unwrap_or_else(|e| e.into_inner());
        let entry = tags.get(&name).ok_or_else(|| status(cip::STATUS_PATH_DESTINATION_UNKNOWN))?;
        let mut resp = Vec::with_capacity(2 + entry.data.len());
        resp.extend_from_slice(&entry.data_type.0.to_le_bytes());
        resp.extend_from_slice(&entry.data);
        Ok(resp)
    }

    // Ref: Rockwell 1756-PM020 Write Tag (0x4D): request data is type code (2 bytes), element
    // count (2 bytes), then the value bytes.
    fn handle_write_tag(&self, path: &Path, data: &[u8]) -> cip::Result<Vec<u8>> {
        let name = parse_symbolic_segment(path).map_err(|_| status(cip::STATUS_PATH_SEGMENT_ERROR))?;
        if data.len() < 4 {
            return Err(status(cip::STATUS_NOT_ENOUGH_DATA));
        }
        let data_type = DataType(u16::from_le_bytes([data[0], data[1]]));
        self.set_tag(&name, data_type, data[4..].to_vec());
        Ok(Vec::new())
    }

    // Ref: CIP Vol. 1, Get_Attribute_All (0x01): here a made-up reply holding the tag count.
    fn handle_get_attribute_all(&self) -> cip::Result<Vec<u8>> {
        let count = self.tags.read().unwrap_or_else(|e| e.into_inner()).len();
        Ok((count as u16).to_le_bytes().to_vec())
    }
}

fn status(s: u8) -> CipError {
    CipError::Status(cip::Error::new(s))
}

impl Object for TagObject {
    fn handle_request(&self, service: u8, path: &Path, data: &[u8]) -> cip::Result<Vec<u8>> {
        match service {
            SERVICE_READ_TAG => self.handle_read_tag(path, data),
            SERVICE_WRITE_TAG => self.handle_write_tag(path, data),
            SERVICE_GET_ATTRIBUTE_ALL => self.handle_get_attribute_all(),
            _ => Err(status(cip::STATUS_SERVICE_NOT_SUPPORTED)),
        }
    }
}

// Ref: CIP Vol. 1, Appendix C EPATH - ANSI Extended Symbol segment: 0x91, length byte, ASCII
// characters (padded to an even length) (section unverified).
fn parse_symbolic_segment(path: &Path) -> Result<String, String> {
    let raw = path.bytes();
    if raw.len() < 2 {
        return Err("path too short for symbolic segment".into());
    }
    if raw[0] != 0x91 {
        return Err(format!("expected symbolic segment (0x91), got 0x{:02X}", raw[0]));
    }
    let n = raw[1] as usize;
    match raw.get(2..2 + n) {
        Some(name) => Ok(String::from_utf8_lossy(name).into_owned()),
        None => Err(format!("path too short for symbol name of length {n}")),
    }
}

// 3.14 is demo data, not an approximation of PI.
#[allow(clippy::approx_constant)]
fn main() {
    let args = Cli::new("ethernetip-server", "Serves Logix-style tags over EtherNet/IP.")
        .flag("addr", ":44818", "TCP address to listen on (host:port)")
        .parse_env();
    let addr = args.str("addr").to_string();

    let logger: Arc<dyn Logger> = Arc::new(DefaultLogger::builder().level(Level::Info).build());
    let router = Arc::new(MessageRouter::new());
    let tag_obj = Arc::new(TagObject::new());

    // Pre-populated tags. Values are little-endian CIP encodings.
    tag_obj.set_tag("MyDINT", TYPE_DINT, 12345i32.to_le_bytes().to_vec());
    tag_obj.set_tag("MyREAL", TYPE_REAL, 3.14f32.to_le_bytes().to_vec());
    let str_value = "Hello, EIP!";
    let mut str_bytes = (str_value.len() as u16).to_le_bytes().to_vec();
    str_bytes.extend_from_slice(str_value.as_bytes());
    tag_obj.set_tag("MySTRING", TYPE_STRING, str_bytes);
    tag_obj.set_tag("Counter", TYPE_DINT, 0i32.to_le_bytes().to_vec());

    // Go registers the tag object under ClassAssembly (0x04) only, but the router sends
    // symbolic-segment (0x91) paths to the symbolic handler, so symbolic Read Tag would never
    // reach it there. Register it for both so the example actually serves tags.
    router.register_object(CLASS_ASSEMBLY, tag_obj.clone());
    router.register_symbolic_handler(tag_obj);

    println!("Pre-populated tags:");
    println!("  MyDINT   (DINT)   = 12345");
    println!("  MyREAL   (REAL)   = 3.14");
    println!("  MySTRING (STRING) = {str_value:?}");
    println!("  Counter  (DINT)   = 0");
    println!();

    let srv = Server::builder(router).logger(logger).build();
    println!("Starting EtherNet/IP server on {addr}...");
    if let Err(e) = srv.start(&Context::background(), &addr) {
        cli::fatal(format!("Failed to start server: {e}"));
    }
    println!("Server is running. Press Ctrl+C to stop.");
    println!();

    cli::install_interrupt_handler();
    while !cli::interrupted() {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    println!("\nReceived signal");
    println!("Shutting down server...");
    if let Err(e) = srv.stop() {
        cli::fatal(format!("Error stopping server: {e}"));
    }
    println!("Server stopped.");
}
