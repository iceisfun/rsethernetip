//! ethernetip-list-tags: enumerates all tags (symbols) on a Rockwell Logix PLC. Port of Go
//! `examples/ethernetip/list_tags`.
//!
//! Logix controllers expose a Symbol Object (class 0x6B) with one instance per tag. The client:
//!  1. queries the class attributes (instance 0) for the maximum instance ID,
//!  2. requests each instance's Name (attribute 1) and Type (attribute 2) with Get_Attribute_List
//!     (service 0x03), and
//!  3. skips instances answering "object does not exist" (0x16).
//!
//! Ref: Rockwell 1756-PM020 Logix 5000 Data Access - Symbol Object (class 0x6B); CIP Vol. 1,
//! Section 3-5 Common Services - Get_Attribute_List (service code 0x03) (section unverified).
//!
//! Program-scoped tags live in per-program symbol tables: `-program <name>` lists one program's
//! tags, `-program all` lists controller tags plus every program's (named `Program:<name>.<tag>`).
//!
//! Usage:
//!   ethernetip-list-tags -addr 192.168.1.10:44818
//!   ethernetip-list-tags -addr 192.168.1.10:44818 -program MainProgram
//!   ethernetip-list-tags -addr 192.168.1.10:44818 -program all

use std::time::Duration;

use rsethernetip::cli::{self, Cli};
use rsethernetip::client;
use rsethernetip::options::{with_retries, with_retry_delay};
use rsethernetip::plc::Context;

fn main() {
    let args = Cli::new("ethernetip-list-tags", "Enumerates tags on a Logix PLC.")
        .flag("addr", "192.168.1.10:44818", "PLC address in host:port format")
        .flag("program", "", "Program name to list, or \"all\" for controller plus every program; empty lists controller scope")
        .parse_env();
    let addr = args.str("addr").to_string();
    let program = args.str("program").to_string();

    // A longer timeout: listing tags is one CIP request per instance ID.
    let ctx = Context::background().with_timeout(Duration::from_secs(60));
    let client = match client::connect(
        &ctx,
        &addr,
        vec![with_retries(2).into(), with_retry_delay(Duration::from_millis(500)).into()],
    ) {
        Ok(c) => c,
        Err(e) => cli::fatal(format!("Failed to connect to {addr}: {e}")),
    };

    println!("Connected to {addr}");
    println!("Enumerating tags via CIP Symbol Object (class 0x6B)...");
    println!();

    // The whole enumeration runs inside one retry-able operation (restarts at instance 1).
    let tags = match program.as_str() {
        "" => client.list_tags(&ctx),
        "all" => client.list_all_tags(&ctx),
        p => client.list_program_tags(&ctx, p),
    };
    let tags = match tags {
        Ok(t) => t,
        Err(e) => cli::fatal(format!("ListTags failed: {e}")),
    };

    if tags.is_empty() {
        println!("No tags found on the controller.");
        println!("This can happen if:");
        println!("  - The controller has no user-defined tags");
        println!("  - External access is restricted for all tags");
        println!("  - The controller firmware does not support symbol enumeration");
        return;
    }

    println!("Found {} tags:\n", tags.len());
    println!("  {:<10}  {:<40}  {}", "Instance", "Name", "Type");
    println!("  {:<10}  {:<40}  {}", "--------", "----", "----");

    for tag in &tags {
        // DataType Display resolves the code to a name; the array bit (0x8000) appends "[]".
        println!("  {:<10}  {:<40}  {} (0x{:04X})", tag.instance_id, tag.name, tag.type_, tag.type_.0);
    }

    println!("\nTotal: {} tags", tags.len());
    println!("\nDone.");
    let _ = client.close();
}
