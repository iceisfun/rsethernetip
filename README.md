# rsethernetip

A zero-dependency Rust port of the EtherNet/IP and CIP stack from `goindustrial/protocol/ethernetip`.
Standard library only (`std::net`, threads, `Mutex`/`Condvar`); no async runtime, `[dependencies]` is empty.

## Features

- EtherNet/IP encapsulation: header, RegisterSession / UnRegisterSession, SendRRData / SendUnitData,
  ListIdentity, ListServices, Common Packet Format.
- CIP: EPATH builder and Logix tag-path parser (`Program:Main.Tag[3].Member`, bit access), Message Router
  request/response, Read/Write Tag (plus fragmented codes), Get_Attribute_Single/List, Symbol Object
  enumeration, Marshal/Unmarshal for basic types, a type registry for custom structures.
- Rockwell types: TIMER, COUNTER, PID, CONTROL.
- PCCC (SLC 500 / MicroLogix / PLC-5 style): address parser, typed read/write frames, `Executor` over
  CIP Execute_PCCC (0x4B).
- Client: sessions, retries, optional auto-reconnect, hex dump, `plc::Reader/Writer/Plc` traits.
- Server/adapter: session handling, `MessageRouter` with pluggable objects, Assembly and Connection
  Manager objects (Forward_Open / Forward_Close).
- Implicit I/O: `IoScanner` (originator, UDP 2222) and `runtime::Runtime` + `Scheduler` (target side).
- 17 example binaries (`ethernetip-*`), see [docs/examples](docs/examples/README.md).

## Module map

| Rust | Go origin | Purpose |
|---|---|---|
| `eip` | `eip/` | encapsulation header, commands, CPF, discovery |
| `cip` | `cip/` | paths, services, router, marshal, symbol, timer/counter |
| `pccc` | `pccc/`, `pccc.go` | PCCC frames, addresses, client, files (`pccc_glue` binds it to `Client`) |
| `objects::{assembly,connmgr}` | `objects/` | Assembly and Connection Manager objects |
| `vendor::rockwell` | `vendor/rockwell` | Timer, Counter, Pid, Control codecs |
| `runtime` | `runtime/` | UDP implicit-I/O target, scheduler |
| `client`, `session`, `conn`, `connector`, `transport`, `options`, `datapoint` | top-level package | connection handling and the tag client |
| `server` | `server.go` | TCP server |
| `io_scanner` | `io.go` | implicit I/O originator |
| `plc`, `logging`, `testutil`, `cli` | `plc/`, `logging/` | protocol-agnostic traits, logger, helpers |

Go `context.Context` became `plc::Context` (a cloneable cancel flag plus deadline); goroutines became
threads; functional options became builders or option enums.

## Usage

Read and write tags:

```rust
use rsethernetip::client::{connect, read_typed};
use rsethernetip::plc::Context;

let ctx = Context::background();
let c = connect(&ctx, "192.168.1.10:44818", vec![])?;
let v: i32 = read_typed(&c, &ctx, "MyDINT")?;
c.write_tag(&ctx, "MyDINT", &(v + 1))?;
let t = c.read_timer(&ctx, "Program:Main.Timer1")?;
println!("{} / {}", t.acc, t.pre);
for s in c.list_tags(&ctx)? { println!("{} {}", s.name, s.type_); }
```

Program-scoped tags and batched reads:

```rust
// Controller scope plus every program; program tags come back as "Program:<name>.<tag>".
for s in c.list_all_tags(&ctx)? { println!("{} {}", s.name, s.type_); }
// One program's tags (bare name or "Program:Main"), names relative to the program.
let main_tags = c.list_program_tags(&ctx, "Main")?;
// Many tags in few round trips (Multiple Service Packet); one entry per name, in order.
// Each entry is the 2-byte type code followed by the data, like read_tag.
let names = ["MyDINT", "Program:Main.Count"];
for (name, r) in names.iter().zip(c.read_tags(&ctx, &names)?) {
    println!("{name}: {:?}", r); // r is a per-tag Result<Vec<u8>>
}
```

Serve tags (any `cip::Object` can be registered under a class or as the symbolic handler):

```rust
use std::sync::Arc;
use rsethernetip::{cip::MessageRouter, plc::Context, server::Server};

let router = Arc::new(MessageRouter::new());
router.register_symbolic_handler(my_tag_object); // impl cip::Object
let srv = Server::new(router);
srv.start(&Context::background(), "0.0.0.0:44818")?;
```

A complete in-memory tag server, symbol enumeration and an I/O scanner/adapter pair are in
`tests/integration.rs`.

## Supported services

| Layer | Services |
|---|---|
| Encapsulation | 0x04 ListServices, 0x63 ListIdentity, 0x65 RegisterSession, 0x66 UnRegisterSession, 0x6F SendRRData, 0x70 SendUnitData |
| CIP | 0x01 Get_Attribute_All, 0x0E Get_Attribute_Single, 0x10 Set_Attribute_Single, 0x03 Get_Attribute_List, 0x4C Read Tag, 0x4D Write Tag, 0x52 Read Tag Fragmented / 0x53 Write Tag Fragmented (codes and encoders), 0x4B Execute_PCCC, 0x54 Forward_Open, 0x4E Forward_Close, 0x5B Large_Forward_Open (structs only) |
| Objects | Assembly (0x04), Connection Manager (0x06, Forward_Open/Close), Symbol (0x6B, client-side enumeration), PCCC (0x67, client-side) |

Not supported: UDP ListIdentity broadcast discovery (TCP only), UnconnectedSend routing, explicit
connected messaging after Forward_Open, a server-side PCCC target, and a server-side Symbol object.

## Specifications and unverified references

Every item carries a `// Ref:` comment. Sources cited: ODVA CIP Vol. 1 (Common Industrial Protocol),
CIP Vol. 2 (EtherNet/IP Adaptation of CIP), Rockwell 1756-PM020 (Logix 5000 Data Access), 1756-RM003
(Logix 5000 General Instructions), Allen-Bradley PCCC / DF1 manual 1770-6.5.16, and Modbus Application
Protocol V1.1b3 for byte-order notes. The ODVA documents were not available while porting, so section and
table numbers were given only where confidently known; roughly 360 references in 46 files are marked
`(section unverified)` or `(table number unverified)` and only name the volume and topic. Grep for
`unverified` to find them.

Possible Go-origin constant errors flagged in comments (kept for fidelity): CIP general status
`PrivilegeViolation`/`DeviceStateConflict`/`ReplyDataTooLarge` look off by one, and the connection manager
extended status `ConnectionNotFound` is 0x0109 where 0x0107 is recalled.

## Testing

```sh
cargo test                 # unit tests and tests/integration.rs
cargo build --all-targets  # warning free
```

Interoperability check: `pycomm3` completes RegisterSession and ListIdentity against `ethernetip-server`.
Its `LogixDriver` needs an Identity object (class 0x01) that the example server does not implement.
