//! Cross-module integration tests: real `Client` <-> real `Server` over loopback TCP, and an
//! IO scanner <-> adapter implicit exchange over loopback UDP. Implementation-detail test
//! harness, not spec. Spec behaviours exercised are cited where they matter.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use rsethernetip::cip::{
    self, CipError, DataType, MessageRouter, Object, Path, CLASS_ASSEMBLY, CLASS_CONNECTION_MGR,
    CLASS_SYMBOL, SERVICE_GET_ATTRIBUTE_LIST, SERVICE_READ_TAG, SERVICE_WRITE_TAG, TYPE_DINT, TYPE_REAL,
    TYPE_STRUCT,
};
use rsethernetip::client::{connect, read_slice, read_typed, Client};
use rsethernetip::datapoint::Tag;
use rsethernetip::eip::{ListIdentityItem, ITEM_ID_LIST_IDENTITY};
use rsethernetip::io_scanner::{IoConnectionConfig, IoScanner};
use rsethernetip::objects::assembly::AssemblyObject;
use rsethernetip::objects::connmgr::ConnectionManager;
use rsethernetip::plc::{self, Context, DataPoint, Reader, Writer};
use rsethernetip::runtime::{IOConnection, Runtime, Scheduler, StopSignal};
use rsethernetip::server::Server;

// Ref: Rockwell 1756-PM020 Logix 5000 Data Access: symbolic tag store served by a test object.
struct Entry {
    header: Vec<u8>, // type code (2 bytes) or struct header (4 bytes)
    elem_size: usize,
    data: Vec<u8>,
}

#[derive(Default)]
struct TagStore {
    tags: RwLock<HashMap<String, Entry>>,
}

impl TagStore {
    fn put(&self, name: &str, t: DataType, elem_size: usize, data: Vec<u8>) {
        self.tags.write().unwrap().insert(name.into(), Entry { header: t.0.to_le_bytes().to_vec(), elem_size, data });
    }
    fn put_struct(&self, name: &str, handle: u16, data: Vec<u8>) {
        let mut h = TYPE_STRUCT.0.to_le_bytes().to_vec();
        h.extend_from_slice(&handle.to_le_bytes());
        let n = data.len();
        self.tags.write().unwrap().insert(name.into(), Entry { header: h, elem_size: n, data });
    }
    fn names(&self) -> Vec<(String, u16)> {
        let t = self.tags.read().unwrap();
        let mut v: Vec<_> = t.iter().map(|(k, e)| (k.clone(), u16::from_le_bytes([e.header[0], e.header[1]]))).collect();
        v.sort();
        v
    }
}

// Ref: CIP Vol. 1, Appendix C EPATH: 0x91 ANSI extended symbol, 0x28/0x29/0x2A member ID (8/16/32).
fn parse_path(p: &Path) -> Option<(String, usize)> {
    let b = p.bytes();
    let (mut i, mut name, mut idx) = (0, String::new(), 0usize);
    while i < b.len() {
        match b[i] {
            0x91 => {
                let n = *b.get(i + 1)? as usize;
                let s = std::str::from_utf8(b.get(i + 2..i + 2 + n)?).ok()?;
                if !name.is_empty() {
                    name.push('.');
                }
                name.push_str(s);
                i += 2 + n + (n % 2);
            }
            0x28 => {
                idx = *b.get(i + 1)? as usize;
                i += 2;
            }
            0x29 => {
                idx = u16::from_le_bytes([*b.get(i + 2)?, *b.get(i + 3)?]) as usize;
                i += 4;
            }
            _ => return None,
        }
    }
    Some((name, idx))
}

fn st(s: u8) -> CipError {
    CipError::Status(cip::Error::new(s))
}

impl Object for TagStore {
    fn handle_request(&self, service: u8, path: &Path, data: &[u8]) -> cip::Result<Vec<u8>> {
        let (name, idx) = parse_path(path).ok_or_else(|| st(cip::STATUS_PATH_SEGMENT_ERROR))?;
        match service {
            SERVICE_READ_TAG => {
                let count = u16::from_le_bytes([*data.first().ok_or_else(|| st(cip::STATUS_NOT_ENOUGH_DATA))?, *data.get(1).ok_or_else(|| st(cip::STATUS_NOT_ENOUGH_DATA))?]) as usize;
                let t = self.tags.read().unwrap();
                let e = t.get(&name).ok_or_else(|| st(cip::STATUS_PATH_DESTINATION_UNKNOWN))?;
                let (s, n) = (idx * e.elem_size, count * e.elem_size);
                let body = e.data.get(s..s + n).ok_or_else(|| st(cip::STATUS_PATH_DESTINATION_UNKNOWN))?;
                let mut out = e.header.clone();
                out.extend_from_slice(body);
                Ok(out)
            }
            SERVICE_WRITE_TAG => {
                if data.len() < 4 {
                    return Err(st(cip::STATUS_NOT_ENOUGH_DATA));
                }
                let mut t = self.tags.write().unwrap();
                let e = t.get_mut(&name).ok_or_else(|| st(cip::STATUS_PATH_DESTINATION_UNKNOWN))?;
                if e.header[..2] != data[..2] {
                    return Err(st(cip::STATUS_INVALID_ATTRIBUTE_VALUE));
                }
                let s = idx * e.elem_size;
                let body = &data[4..];
                e.data.get_mut(s..s + body.len()).ok_or_else(|| st(cip::STATUS_PATH_DESTINATION_UNKNOWN))?.copy_from_slice(body);
                Ok(Vec::new())
            }
            _ => Err(st(cip::STATUS_SERVICE_NOT_SUPPORTED)),
        }
    }
}

// Ref: Rockwell 1756-PM020 Symbol Object (class 0x6B), Get_Attribute_List (0x03).
struct SymbolObj(Arc<TagStore>);

impl Object for SymbolObj {
    fn handle_request(&self, service: u8, path: &Path, _data: &[u8]) -> cip::Result<Vec<u8>> {
        if service != SERVICE_GET_ATTRIBUTE_LIST {
            return Err(st(cip::STATUS_SERVICE_NOT_SUPPORTED));
        }
        let names = self.0.names();
        let b = path.bytes();
        // The router strips the class segment: instance 0x24 n, 0x25 pad u16 or 0x26 pad u32.
        let inst = match b.first() {
            Some(0x24) => *b.get(1).unwrap_or(&0) as usize,
            Some(0x25) => u16::from_le_bytes([*b.get(2).unwrap_or(&0), *b.get(3).unwrap_or(&0)]) as usize,
            Some(0x26) => u32::from_le_bytes([*b.get(2).unwrap_or(&0), *b.get(3).unwrap_or(&0), *b.get(4).unwrap_or(&0), *b.get(5).unwrap_or(&0)]) as usize,
            _ => return Err(st(cip::STATUS_PATH_SEGMENT_ERROR)),
        };
        let mut out = 2u16.to_le_bytes().to_vec();
        if inst == 0 {
            out.extend_from_slice(&[1, 0, 0, 0, 1, 0]); // attr 1 ok, rev 1
            out.extend_from_slice(&[2, 0, 0, 0]);
            out.extend_from_slice(&(names.len() as u16).to_le_bytes());
        } else {
            let (n, t) = names.get(inst - 1).ok_or_else(|| st(cip::STATUS_PATH_DESTINATION_UNKNOWN))?;
            out.extend_from_slice(&[1, 0, 0, 0]);
            out.extend_from_slice(&(n.len() as u16).to_le_bytes());
            out.extend_from_slice(n.as_bytes());
            out.extend_from_slice(&[2, 0, 0, 0]);
            out.extend_from_slice(&t.to_le_bytes());
        }
        Ok(out)
    }
}

fn start_server() -> (Server, Arc<TagStore>, String) {
    let store = Arc::new(TagStore::default());
    store.put("MyDINT", TYPE_DINT, 4, 12345i32.to_le_bytes().to_vec());
    store.put("MyREAL", TYPE_REAL, 4, 3.5f32.to_le_bytes().to_vec());
    store.put("Prog.Local", TYPE_DINT, 4, 7i32.to_le_bytes().to_vec());
    store.put("Arr", TYPE_DINT, 4, [10i32, 20, 30, 40].iter().flat_map(|v| v.to_le_bytes()).collect());
    // TIMER in the canonical 14-byte layout (reserved, status, PRE, ACC).
    let timer = cip::marshal(&cip::Timer { pre: 5000, acc: 1200, en: true, tt: true, dn: false }).unwrap();
    store.put_struct("MyTimer", 0x0F83, timer);

    let router = Arc::new(MessageRouter::new());
    router.register_symbolic_handler(store.clone());
    router.register_object(CLASS_SYMBOL, Arc::new(SymbolObj(store.clone())));
    let srv = Server::builder(router)
        .identity(ListIdentityItem {
            type_id: ITEM_ID_LIST_IDENTITY,
            encaps_version: 1,
            vendor_id: 0x1234,
            device_type: 14,
            product_code: 99,
            revision: [2, 3],
            serial_number: 0xCAFE,
            product_name: "RS Test PLC".into(),
            ..Default::default()
        })
        .build();
    srv.start(&Context::background(), "127.0.0.1:0").unwrap();
    let addr = srv.local_addr().unwrap().to_string();
    (srv, store, addr)
}

fn client(addr: &str) -> Client {
    connect(&Context::background().with_timeout(Duration::from_secs(5)), addr, vec![]).unwrap()
}

#[test]
fn read_write_scalar_tags() {
    let (srv, _s, addr) = start_server();
    let c = client(&addr);
    let ctx = Context::background();
    assert_eq!(read_typed::<i32>(&c, &ctx, "MyDINT").unwrap(), 12345);
    assert_eq!(read_typed::<f32>(&c, &ctx, "MyREAL").unwrap(), 3.5);
    c.write_tag(&ctx, "MyDINT", &-99i32).unwrap();
    assert_eq!(read_typed::<i32>(&c, &ctx, "MyDINT").unwrap(), -99);
    // Raw read carries the 2-byte type prefix.
    let raw = c.read_tag(&ctx, "MyDINT").unwrap();
    assert_eq!(raw, [&TYPE_DINT.0.to_le_bytes()[..], &(-99i32).to_le_bytes()[..]].concat());
    c.close().unwrap();
    srv.stop().unwrap();
}

#[test]
fn arrays_and_program_scoped_tags() {
    let (srv, _s, addr) = start_server();
    let c = client(&addr);
    let ctx = Context::background();
    assert_eq!(read_slice::<i32>(&c, &ctx, "Arr", 4).unwrap(), vec![10, 20, 30, 40]);
    assert_eq!(read_slice::<i32>(&c, &ctx, "Arr[2]", 2).unwrap(), vec![30, 40]);
    c.write_tag(&ctx, "Arr[1]", &21i32).unwrap();
    assert_eq!(read_slice::<i32>(&c, &ctx, "Arr", 4).unwrap(), vec![10, 21, 30, 40]);
    let mut dst = [0i32; 2];
    c.read_tag_elements_into(&ctx, "Arr", 2, &mut dst[..]).unwrap();
    assert_eq!(dst, [10, 21]);
    // Program-scoped path is two symbolic segments in this server's flattened store.
    assert_eq!(read_typed::<i32>(&c, &ctx, "Prog.Local").unwrap(), 7);
    // Out of range array read comes back as a CIP status error.
    assert!(c.read_tag_elements(&ctx, "Arr", 100).is_err());
    assert!(c.read_tag_elements(&ctx, "Arr", 0).is_err());
    srv.stop().unwrap();
}

#[test]
fn struct_timer_read() {
    let (srv, _s, addr) = start_server();
    let c = client(&addr);
    let t = c.read_timer(&Context::background(), "MyTimer").unwrap();
    assert_eq!((t.pre, t.acc), (5000, 1200));
    assert!(t.en && t.tt && !t.dn);
    srv.stop().unwrap();
}

#[test]
fn unknown_tag_is_cip_error_and_not_retried() {
    let (srv, _s, addr) = start_server();
    let c = client(&addr);
    let err = c.read_tag(&Context::background(), "Nope").unwrap_err();
    assert!(err.to_string().to_lowercase().contains("cip") || err.to_string().contains("0x05"), "{err}");
    // Connection is still usable.
    assert_eq!(read_typed::<i32>(&c, &Context::background(), "MyDINT").unwrap(), 12345);
    srv.stop().unwrap();
}

#[test]
fn list_tags_and_discovery() {
    let (srv, store, addr) = start_server();
    let c = client(&addr);
    let ctx = Context::background();
    let tags = c.list_tags(&ctx).unwrap();
    let got: Vec<String> = tags.iter().map(|t| t.name.clone()).collect();
    let want: Vec<String> = store.names().into_iter().map(|(n, _)| n).collect();
    assert_eq!(got, want);

    let ids = c.list_identity(&ctx).unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].product_name, "RS Test PLC");
    assert_eq!((ids[0].vendor_id, ids[0].product_code, ids[0].revision), (0x1234, 99, [2, 3]));
    assert_eq!(ids[0].serial_number, 0xCAFE);

    let svcs = c.list_services(&ctx).unwrap();
    assert!(!svcs.is_empty());
    srv.stop().unwrap();
}

#[test]
fn plc_reader_writer_traits() {
    let (srv, _s, addr) = start_server();
    let c = client(&addr);
    let ctx = Context::background();
    let dp: Arc<dyn DataPoint> = Arc::new(Tag::new("MyDINT"));
    let vals = Reader::read(&c, &ctx, std::slice::from_ref(&dp)).unwrap();
    assert_eq!(vals.len(), 1);
    assert_eq!(vals[0].int().unwrap(), 12345);
    let mut raw = TYPE_DINT.0.to_le_bytes().to_vec();
    raw.extend_from_slice(&777i32.to_le_bytes());
    Writer::write(&c, &ctx, dp.as_ref(), &raw).unwrap();
    assert_eq!(read_typed::<i32>(&c, &ctx, "MyDINT").unwrap(), 777);
    let _: &dyn plc::Plc = &c;
    srv.stop().unwrap();
}

#[test]
fn many_concurrent_clients() {
    let (srv, _s, addr) = start_server();
    let hs: Vec<_> = (0..8)
        .map(|_| {
            let a = addr.clone();
            std::thread::spawn(move || {
                let c = client(&a);
                for _ in 0..25 {
                    assert!(read_typed::<i32>(&c, &Context::background(), "Arr").is_ok());
                }
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
    srv.stop().unwrap();
}

#[test]
fn reconnecting_client_and_server_client_tracking() {
    let (srv, _s, addr) = start_server();
    let c = rsethernetip::client::new_reconnecting_client(&addr, vec![]);
    let ctx = Context::background().with_timeout(Duration::from_secs(5));
    assert_eq!(read_typed::<i32>(&c, &ctx, "MyDINT").unwrap(), 12345);
    assert_eq!(srv.connected_clients().len(), 1);
    srv.stop().unwrap();
}

// Ref: CIP Vol. 1, Chapter 3 Connection Management (Forward_Open) + implicit I/O over UDP 2222.
#[test]
fn io_scanner_exchanges_with_adapter() {
    let ao = Arc::new(AssemblyObject::new());
    ao.register_assembly(100, vec![0; 4]);
    ao.register_assembly(101, vec![0xA5, 0x5A, 0x01, 0x02]);
    let rt = Runtime::new(ao.clone());
    rt.start("127.0.0.1:0").unwrap();
    let sched = Scheduler::new(&rt);
    sched.start();
    let udp = rt.addr().unwrap();

    let opened = Arc::new(Mutex::new(Vec::<u32>::new()));
    let closed = Arc::new(AtomicBool::new(false));
    let (rt1, ao1, op) = (rt.clone(), ao.clone(), opened.clone());
    let (rt2, cl) = (rt.clone(), closed.clone());
    let cm = ConnectionManager::new()
        .with_on_open(move |c, req| {
            let rpi = Duration::from_micros(req.ot_rpi as u64).max(Duration::from_millis(5));
            rt1.add_connection(IOConnection {
                connection_id: c.ot_connection_id,
                rpi,
                assembly: ao1.get_instance(100),
                is_consumer: true,
                timeout_mult: req.connection_timeout_multiplier,
                stop_chan: Some(StopSignal::new()),
                ..Default::default()
            });
            rt1.add_connection(IOConnection {
                connection_id: c.to_connection_id,
                rpi,
                assembly: ao1.get_instance(101),
                is_producer: true,
                stop_chan: Some(StopSignal::new()),
                ..Default::default()
            });
            op.lock().unwrap().push(c.to_connection_id);
        })
        .with_on_close(move |c| {
            rt2.remove_connection(c.ot_connection_id);
            rt2.remove_connection(c.to_connection_id);
            cl.store(true, Ordering::SeqCst);
        });
    let router = Arc::new(MessageRouter::new());
    router.register_object(CLASS_CONNECTION_MGR, Arc::new(cm));
    router.register_object(CLASS_ASSEMBLY, ao.clone());
    let srv = Server::builder(router).build();
    srv.start(&Context::background(), "127.0.0.1:0").unwrap();
    let addr = srv.local_addr().unwrap().to_string();

    let ctx = Context::background().with_timeout(Duration::from_secs(10));
    let sess = rsethernetip::session::Session::new(rsethernetip::conn::TcpConn::new(&addr, &[]).unwrap(), None);
    let sess = Arc::new(sess);
    sess.register(&ctx).unwrap();
    let scanner = IoScanner::new(sess.clone(), "127.0.0.1:0", &[]).unwrap();

    let mut p = Path::new();
    p.add_class(CLASS_ASSEMBLY);
    p.add_instance(1);
    p.add_connection_point(100);
    p.add_connection_point(101);
    let conn = scanner
        .open(
            &ctx,
            &IoConnectionConfig {
                ot_connection_point: 100,
                to_connection_point: 101,
                config_instance: 1,
                ot_size: 4,
                to_size: 4,
                rpi: Duration::from_millis(20),
                timeout_multiplier: 2,
                target_addr: Some(udp),
                connection_path: Some(p.bytes().to_vec()),
                ..Default::default()
            },
        )
        .unwrap();
    // The adapter does not know the scanner's UDP endpoint (see README); tell it explicitly.
    let local = scanner.local_addr().unwrap();
    rt.set_producer_addr(conn.to_connection_id, format!("127.0.0.1:{}", local.port()).parse().unwrap());

    conn.set_output(&[1, 2, 3, 4]).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let out_ok = ao.get_instance(100).unwrap().data() == [1, 2, 3, 4];
        let in_ok = conn.input() == [0xA5, 0x5A, 0x01, 0x02];
        if out_ok && in_ok {
            break;
        }
        assert!(Instant::now() < deadline, "no I/O exchange: out_ok={out_ok} in_ok={in_ok}");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!conn.is_timed_out());

    scanner.close(&ctx, &conn).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while !closed.load(Ordering::SeqCst) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(closed.load(Ordering::SeqCst));
    scanner.shutdown(&ctx).unwrap();
    sched.stop();
    rt.stop();
    srv.stop().unwrap();
}
