//! Implicit (class 1, cyclic) I/O scanner: CIP Forward_Open / Forward_Close over a TCP
//! [`Session`] plus cyclic assembly exchange over UDP.
//!
//! Port of Go `io.go`.

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::cip::{self, MessageRouterRequest, Path};
use crate::conn::{Error, Result};
use crate::eip::{ITEM_ID_CONNECTED_DATA, ITEM_ID_SEQUENCED_ADDRESS};
use crate::logging::{Logger, NopLogger};
use crate::objects::connmgr::{
    self, ForwardCloseRequest, ForwardOpenRequest, CONN_PARAM_FIXED_SIZE, CONN_PARAM_POINT_TO_POINT,
};
use crate::plc::Context;
use crate::session::Session;

// Ref: ODVA EtherNet/IP Adaptation of CIP (CIP Vol. 2), implicit (I/O) messaging uses UDP port
// 0x08AE = 2222 (section unverified).
const IO_UDP_PORT: u16 = 2222;

// Implementation detail (not spec): granularity at which background threads re-check their
// stop flags, since std offers no way to interrupt a blocking socket read or sleep.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

// Implementation detail (not spec): poison-tolerant lock helpers.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// Ref: CIP Vol. 1, Connection Manager Object, Forward_Open parameters (section unverified).
// IOConnectionConfig describes the parameters for establishing an implicit I/O connection via
// CIP Forward_Open. Implicit connections exchange assembly data cyclically over UDP at the
// Requested Packet Interval (RPI).
/// Parameters for establishing an implicit I/O connection.
#[derive(Clone, Debug, Default)]
pub struct IoConnectionConfig {
    /// Target assembly instance for O->T data.
    pub ot_connection_point: u16,
    /// Target assembly instance for T->O data.
    pub to_connection_point: u16,
    /// Target configuration assembly (0 = none).
    pub config_instance: u16,
    /// Output assembly size in bytes.
    pub ot_size: u16,
    /// Input assembly size in bytes.
    pub to_size: u16,
    /// Requested Packet Interval for cyclic data exchange.
    pub rpi: Duration,
    // Ref: CIP Vol. 1, Forward_Open Connection Timeout Multiplier (section unverified).
    /// Controls the watchdog: timeout = RPI * (4 << mult).
    pub timeout_multiplier: u8,
    // Ref: CIP Vol. 2, 32-bit Run/Idle header on class 1 O->T data (section unverified).
    /// Adds a 4-byte run/idle header to each packet.
    pub run_idle_header: bool,
    /// UDP address to send O->T data to. If `None`, the scanner resolves it from the TCP
    /// session's remote address + port 2222.
    pub target_addr: Option<SocketAddr>,
    /// Overrides the auto-generated connection path. If `None`, the scanner builds a standard
    /// path from the assembly instances: [Class 0x04, Instance config, ConnPt OT, ConnPt TO].
    pub connection_path: Option<Vec<u8>>,
}

// Implementation detail: replaces Go's functional `IOScannerOption`.
/// An option for [`IoScanner::new`].
#[derive(Clone)]
pub enum IoScannerOption {
    /// Logger for the scanner (Go `WithIOLogger`).
    Logger(Arc<dyn Logger>),
    /// Originator vendor ID for Forward_Open (Go `WithVendorID`), default 1.
    VendorId(u16),
    /// Originator serial number for Forward_Open (Go `WithOriginatorSerial`), default 1.
    OriginatorSerial(u32),
}

/// Sets the logger for the I/O scanner.
pub fn with_io_logger(l: Arc<dyn Logger>) -> IoScannerOption {
    IoScannerOption::Logger(l)
}

// Ref: CIP Vol. 1, Forward_Open "Originator Vendor ID" (connection triad, section unverified).
/// Sets the originator vendor ID included in Forward_Open requests (default 1).
pub fn with_vendor_id(id: u16) -> IoScannerOption {
    IoScannerOption::VendorId(id)
}

// Ref: CIP Vol. 1, Forward_Open "Originator Serial Number" (connection triad, section
// unverified).
/// Sets the originator serial number included in Forward_Open requests (default 1).
pub fn with_originator_serial(sn: u32) -> IoScannerOption {
    IoScannerOption::OriginatorSerial(sn)
}

// Implementation detail (not spec): state shared between the scanner handle and its worker
// threads (Go `IOScanner` fields used by the goroutines).
struct Shared {
    session: Arc<Session>,
    udp: UdpSocket,
    // Held for parity with the Go scanner; the Go code never logs through it.
    #[allow(dead_code)]
    logger: Arc<dyn Logger>,
    vendor_id: u16,
    originator_sn: u32,
    // Keyed by TOConnectionID (what we receive on).
    connections: RwLock<HashMap<u32, Arc<IoConn>>>,
    next_ot_id: AtomicU32,
    next_serial: AtomicU32,
    // Go `done` channel.
    done: AtomicBool,
}

// Implementation detail: Go `IOScanner` (control plane over TCP session, data plane over UDP).
/// Manages implicit (cyclic) I/O connections over EtherNet/IP. Uses a TCP [`Session`] for CIP
/// Forward_Open / Forward_Close and a local UDP socket for producing and consuming assembly
/// data at the negotiated RPI.
pub struct IoScanner {
    shared: Arc<Shared>,
    // Go `wg`: joined on shutdown.
    threads: Mutex<Vec<JoinHandle<()>>>,
}

// Ref: CIP Vol. 1, Connection Manager Object - connection IDs and connection triad (section
// unverified).
/// An active implicit I/O connection established by [`IoScanner::open`]. Assembly data is
/// exchanged cyclically over UDP at the negotiated RPI. Use [`IoConn::set_output`] to update the
/// Originator-to-Target (O-T) assembly and [`IoConn::input`] to read the latest
/// Target-to-Originator (T-O) assembly data.
pub struct IoConn {
    // Connection identifiers (read-only after creation).
    pub ot_connection_id: u32,
    pub to_connection_id: u32,
    pub connection_serial_number: u16,
    pub vendor_id: u16,
    pub originator_serial_number: u32,

    output_data: RwLock<Vec<u8>>,
    input_data: RwLock<Vec<u8>>,

    /// Actual negotiated packet interval.
    pub rpi: Duration,
    sequence_count: AtomicU16,
    last_receive: Mutex<Instant>,
    timeout_mult: u8,
    run_idle_header: bool,
    remote_addr: Option<SocketAddr>,

    // Implementation detail: Go `stopCh` + `sync.Once`; the condvar wakes the producer thread.
    stop: (Mutex<bool>, Condvar),
}

impl IoScanner {
    // Implementation detail (not spec): binds the UDP socket and starts the receive thread.
    /// Creates an I/O scanner that uses `session` for Forward_Open/Close and binds a UDP socket
    /// to `local_udp_addr` for cyclic data exchange. Pass `"0.0.0.0:0"` or `"127.0.0.1:0"` to
    /// let the OS choose an ephemeral port (Go also accepted `":0"`, which is mapped to
    /// `0.0.0.0:0`). A background thread is started to receive incoming T-O packets.
    pub fn new(session: Arc<Session>, local_udp_addr: &str, opts: &[IoScannerOption]) -> Result<IoScanner> {
        // Go `net.ResolveUDPAddr` accepts ":port" (wildcard host).
        let addr_str = if local_udp_addr.starts_with(':') { format!("0.0.0.0{local_udp_addr}") } else { local_udp_addr.to_string() };
        let udp = UdpSocket::bind(addr_str.as_str()).map_err(|e| {
            // Go distinguishes resolve and bind failures; std reports both from bind.
            Error::wrap("bind UDP", Error::Io(e))
        })?;
        udp.set_read_timeout(Some(POLL_INTERVAL)).map_err(|e| Error::wrap("bind UDP", Error::Io(e)))?;

        let mut shared = Shared {
            session,
            udp,
            logger: Arc::new(NopLogger::new()),
            vendor_id: 1,
            originator_sn: 1,
            connections: RwLock::new(HashMap::new()),
            next_ot_id: AtomicU32::new(0),
            next_serial: AtomicU32::new(0),
            done: AtomicBool::new(false),
        };
        for opt in opts {
            match opt {
                IoScannerOption::Logger(l) => shared.logger = l.clone(),
                IoScannerOption::VendorId(v) => shared.vendor_id = *v,
                IoScannerOption::OriginatorSerial(s) => shared.originator_sn = *s,
            }
        }
        let shared = Arc::new(shared);

        let s2 = shared.clone();
        let h = std::thread::spawn(move || s2.receive_loop());

        Ok(IoScanner { shared, threads: Mutex::new(vec![h]) })
    }

    // Implementation detail: lets callers (and tests) find the scanner's UDP endpoint
    // (Go tests read `scanner.udpConn.LocalAddr()`).
    /// Returns the local address of the scanner's UDP socket.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.shared.udp.local_addr()
    }

    // Ref: CIP Vol. 1, Connection Manager Object, Forward_Open service 0x54 sent to class 0x06
    // instance 1 (section unverified); response layout per Forward_Open success reply.
    /// Establishes an implicit I/O connection by sending a CIP Forward_Open over TCP and, on
    /// success, starting a background thread that produces O-T assembly data over UDP at the
    /// negotiated RPI.
    pub fn open(&self, ctx: &Context, cfg: &IoConnectionConfig) -> Result<Arc<IoConn>> {
        let s = &self.shared;
        let ot_conn_id = s.next_ot_id.fetch_add(1, Ordering::SeqCst).wrapping_add(1);
        // Originator-proposed T->O connection ID, unique per open (high bit set so it never
        // collides with the O->T proposal sequence). Bit 30 rather than bit 31 is used so it also
        // cannot collide with IDs the target allocates (this crate's ConnectionManager counts up
        // from 0x8000_0000), which would make both directions share one connection-table slot.
        let to_proposal = ot_conn_id | 0x4000_0000;
        // Go converts the 32-bit counter to cip.UINT (truncating).
        let serial = s.next_serial.fetch_add(1, Ordering::SeqCst).wrapping_add(1) as u16;

        // Build connection path using connection points (0x2C segments).
        // Standard Logix format: [Class 0x04] [Instance config] [ConnPt OT] [ConnPt TO]
        let conn_path: Vec<u8> = match &cfg.connection_path {
            Some(p) => p.clone(),
            None => {
                let mut p = Path::new();
                p.add_class(cip::CLASS_ASSEMBLY);
                if cfg.config_instance > 0 {
                    p.add_instance(cfg.config_instance);
                } else {
                    p.add_instance(1);
                }
                p.add_connection_point(cfg.ot_connection_point);
                p.add_connection_point(cfg.to_connection_point);
                p.bytes().to_vec()
            }
        };

        // Ref: CIP Vol. 1, Forward_Open O->T / T->O RPI in microseconds (section unverified).
        // Go truncates the int64 microsecond count to UDINT.
        let rpi_micros = cfg.rpi.as_micros() as u32;

        // Ref: CIP Vol. 1, Network Connection Parameters: connection type, fixed/variable size,
        // size in bytes (section unverified).
        let ot_params = CONN_PARAM_POINT_TO_POINT | CONN_PARAM_FIXED_SIZE | cfg.ot_size;
        let to_params = CONN_PARAM_POINT_TO_POINT | CONN_PARAM_FIXED_SIZE | cfg.to_size;

        let fo_req = ForwardOpenRequest {
            priority_time_tick: 0x0A,
            timeout_ticks: 0xF0,
            // Ref: CIP Vol. 1, Connection Manager, Forward_Open connection ID selection (section
            // unverified): the target selects the O->T connection ID (the reply value is
            // authoritative) while the originator proposes the T->O connection ID. Both are
            // proposed here and the reply values are used afterwards.
            ot_connection_id: ot_conn_id,
            to_connection_id: to_proposal,
            connection_serial_number: serial,
            vendor_id: s.vendor_id,
            originator_serial_number: s.originator_sn,
            connection_timeout_multiplier: cfg.timeout_multiplier,
            ot_rpi: rpi_micros,
            ot_network_connection_params: ot_params,
            to_rpi: rpi_micros,
            to_network_connection_params: to_params,
            // Ref: CIP Vol. 1, Connection Manager, Transport Class and Trigger (section
            // unverified): 0x01 = Direction=client (bit 7=0), Production trigger=cyclic
            // (bits 6-4=0), Transport class 1 (bits 3-0).
            transport_type_trigger: 0x01,
            connection_path: conn_path,
            ..Default::default()
        };

        let fo_data = fo_req.encode().map_err(|e| Error::wrap("encode Forward_Open", e.into()))?;

        let mut mr_path = Path::new();
        mr_path.add_class(cip::CLASS_CONNECTION_MGR);
        mr_path.add_instance(1);

        let mr_req = MessageRouterRequest {
            service: connmgr::SERVICE_FORWARD_OPEN,
            request_path: mr_path,
            request_data: fo_data,
        };

        let resp = s.session.send_cip_request(ctx, &mr_req).map_err(|e| Error::wrap("Forward_Open send", e))?;
        if !resp.is_success() {
            let ext = match resp.ext_status.first() {
                Some(x) => format!(", ext status 0x{x:04X}"),
                None => String::new(),
            };
            return Err(Error::msg(format!("Forward_Open failed: general status 0x{:02X}{}", resp.general_status, ext)));
        }

        // Parse ForwardOpenResponse (26 bytes minimum: OT+TO conn IDs + triad + APIs + reply
        // size + reserved).
        let rd = &resp.response_data;
        if rd.len() < 26 {
            return Err(Error::msg(format!("Forward_Open response too short: {} bytes", rd.len())));
        }
        // Ref: CIP Vol. 1, Forward_Open reply (section unverified): O->T connection ID at
        // bytes 0..4 (selected by the target), T->O connection ID at bytes 4..8.
        let ot_conn_id = u32::from_le_bytes([rd[0], rd[1], rd[2], rd[3]]);
        let mut to_conn_id = u32::from_le_bytes([rd[4], rd[5], rd[6], rd[7]]);
        if to_conn_id == 0 {
            to_conn_id = to_proposal;
        }
        let ot_api_us = u32::from_le_bytes([rd[16], rd[17], rd[18], rd[19]]);
        let mut ot_api = Duration::from_micros(ot_api_us as u64);
        if ot_api.is_zero() {
            ot_api = cfg.rpi;
        }

        // Resolve target UDP address.
        let target_addr = match cfg.target_addr {
            Some(a) => a,
            None => match s.session.peer_addr() {
                Some(peer) => SocketAddr::new(peer.ip(), IO_UDP_PORT),
                None => return Err(Error::msg("cannot resolve target UDP address")),
            },
        };

        let conn = Arc::new(IoConn {
            ot_connection_id: ot_conn_id,
            to_connection_id: to_conn_id,
            connection_serial_number: serial,
            vendor_id: s.vendor_id,
            originator_serial_number: s.originator_sn,
            output_data: RwLock::new(vec![0u8; cfg.ot_size as usize]),
            input_data: RwLock::new(vec![0u8; cfg.to_size as usize]),
            rpi: ot_api,
            sequence_count: AtomicU16::new(0),
            last_receive: Mutex::new(Instant::now()),
            timeout_mult: cfg.timeout_multiplier,
            run_idle_header: cfg.run_idle_header,
            remote_addr: Some(target_addr),
            stop: (Mutex::new(false), Condvar::new()),
        });

        s.connections.write().unwrap_or_else(|e| e.into_inner()).insert(to_conn_id, conn.clone());

        // Implementation detail: producer thread (Go goroutine), joined by `shutdown`.
        let (sh, c2) = (s.clone(), conn.clone());
        let h = std::thread::spawn(move || c2.produce_loop(&sh));
        {
            // Implementation detail: reap finished producer threads so repeated open/close
            // cycles do not accumulate unjoined handles.
            let mut threads = lock(&self.threads);
            let mut i = 0;
            while i < threads.len() {
                if threads[i].is_finished() {
                    let _ = threads.swap_remove(i).join();
                } else {
                    i += 1;
                }
            }
            threads.push(h);
        }

        Ok(conn)
    }

    // Ref: CIP Vol. 1, Connection Manager Object, Forward_Close service 0x4E (section
    // unverified); the connection is identified by its triad.
    /// Sends a CIP Forward_Close for `conn` and stops its cyclic output producer thread.
    pub fn close(&self, ctx: &Context, conn: &IoConn) -> Result<()> {
        let s = &self.shared;
        conn.signal_stop();

        s.connections.write().unwrap_or_else(|e| e.into_inner()).remove(&conn.to_connection_id);

        let mut conn_path = Path::new();
        conn_path.add_class(cip::CLASS_ASSEMBLY);
        conn_path.add_instance(1);

        let fc_req = ForwardCloseRequest {
            priority_time_tick: 0x0A,
            timeout_ticks: 0xF0,
            connection_serial_number: conn.connection_serial_number,
            vendor_id: conn.vendor_id,
            originator_serial_number: conn.originator_serial_number,
            connection_path: conn_path.bytes().to_vec(),
            ..Default::default()
        };

        let fc_data = fc_req.encode().map_err(|e| Error::wrap("encode Forward_Close", e.into()))?;

        let mut mr_path = Path::new();
        mr_path.add_class(cip::CLASS_CONNECTION_MGR);
        mr_path.add_instance(1);

        let mr_req = MessageRouterRequest {
            service: connmgr::SERVICE_FORWARD_CLOSE,
            request_path: mr_path,
            request_data: fc_data,
        };

        let resp = s.session.send_cip_request(ctx, &mr_req).map_err(|e| Error::wrap("Forward_Close send", e))?;
        if !resp.is_success() {
            return Err(Error::msg(format!("Forward_Close failed: status 0x{:02X}", resp.general_status)));
        }
        Ok(())
    }

    // Implementation detail: stops the worker threads (Go closes `done`, closes the UDP socket
    // and waits on the WaitGroup).
    /// Sends Forward_Close for every active connection, stops the UDP threads, and waits for all
    /// background threads to exit. Returns the first Forward_Close error, if any.
    pub fn shutdown(&self, ctx: &Context) -> Result<()> {
        let conns: Vec<Arc<IoConn>> =
            self.shared.connections.read().unwrap_or_else(|e| e.into_inner()).values().cloned().collect();

        let mut first_err: Option<Error> = None;
        for c in &conns {
            if let Err(e) = self.close(ctx, c)
                && first_err.is_none() {
                    first_err = Some(e);
                }
        }

        self.shared.done.store(true, Ordering::SeqCst);
        self.join_threads();

        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    // Implementation detail: waits for every worker thread.
    fn join_threads(&self) {
        let handles: Vec<JoinHandle<()>> = std::mem::take(&mut *lock(&self.threads));
        for h in handles {
            let _ = h.join();
        }
    }
}

// Implementation detail: make sure worker threads never outlive an un-shutdown scanner.
impl Drop for IoScanner {
    fn drop(&mut self) {
        self.shared.done.store(true, Ordering::SeqCst);
        self.join_threads();
    }
}

// Implementation detail: walks the CPF items by type and length (no fixed offsets) and returns
// the connection ID from the Sequenced Address item plus the Connected Data item payload.
// Ref: CIP Vol. 2, Common Packet Format item layout: Type ID (UINT), Length (UINT), data (section
// unverified).
fn parse_io_packet(data: &[u8]) -> Option<(u32, &[u8])> {
    let count = u16::from_le_bytes([*data.first()?, *data.get(1)?]);
    if count != 2 {
        return None;
    }
    let mut off = 2usize;
    let mut conn_id: Option<u32> = None;
    let mut payload: Option<&[u8]> = None;
    for _ in 0..count {
        let hdr = data.get(off..off.checked_add(4)?)?;
        let ty = u16::from_le_bytes([hdr[0], hdr[1]]);
        let len = u16::from_le_bytes([hdr[2], hdr[3]]) as usize;
        let body = data.get(off + 4..(off + 4).checked_add(len)?)?;
        off += 4 + len;
        if ty == ITEM_ID_SEQUENCED_ADDRESS {
            if len != 8 {
                return None;
            }
            conn_id = Some(u32::from_le_bytes([body[0], body[1], body[2], body[3]]));
        } else if ty == ITEM_ID_CONNECTED_DATA {
            payload = Some(body);
        }
    }
    Some((conn_id?, payload?))
}

impl Shared {
    // Implementation detail: Go `receiveLoop`. Reads UDP packets and dispatches them to the
    // matching IoConn. The socket has a short read timeout so the `done` flag is observed.
    fn receive_loop(&self) {
        let mut buf = [0u8; 2048];
        loop {
            if self.done.load(Ordering::SeqCst) {
                return;
            }
            match self.udp.recv_from(&mut buf) {
                Ok((n, _)) => self.handle_incoming_packet(&buf[..n]),
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted) => {}
                // Implementation detail: on some platforms (e.g. Windows WSAECONNRESET) an ICMP
                // port-unreachable from an earlier send_to surfaces as a recv error; it is
                // transient and must not kill the receive thread.
                Err(e) if matches!(e.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused) => {}
                Err(_) => return,
            }
        }
    }

    // Ref: CIP Vol. 2, Common Packet Format (section unverified), as used by class 1 I/O over
    // UDP: Sequenced Address item (0x8002, length 8: 32-bit connection ID + 32-bit sequence
    // number) + Connected Data item (0x00B1: 16-bit sequence count + optional 32-bit run/idle
    // header + assembly data) (section for I/O framing unverified).
    // Parses a T-O packet and stores its assembly data into the matching connection.
    fn handle_incoming_packet(&self, data: &[u8]) {
        let (conn_id, payload) = match parse_io_packet(data) {
            Some(x) => x,
            None => return,
        };

        let conn = match self.connections.read().unwrap_or_else(|e| e.into_inner()).get(&conn_id) {
            Some(c) => c.clone(),
            None => return,
        };

        // Skip sequence count (2 bytes)
        let mut offset = 2;
        if conn.run_idle_header {
            offset += 4; // skip run/idle header
        }
        if offset > payload.len() {
            return;
        }

        let assembly_data = &payload[offset..];

        {
            let mut input = conn.input_data.write().unwrap_or_else(|e| e.into_inner());
            if assembly_data.len() == input.len() {
                input.copy_from_slice(assembly_data);
            }
        }
        *lock(&conn.last_receive) = Instant::now();
    }
}

impl IoConn {
    // Implementation detail: Go `stopMu.Do(close(stopCh))`.
    fn signal_stop(&self) {
        *lock(&self.stop.0) = true;
        self.stop.1.notify_all();
    }

    fn is_stopped(&self) -> bool {
        *lock(&self.stop.0)
    }

    // Ref: CIP Vol. 2, class 1 connections are produced cyclically at the RPI (section
    // unverified).
    /// Updates the Originator-to-Target assembly data sent each cycle. The length of `data` must
    /// match the configured `ot_size`.
    pub fn set_output(&self, data: &[u8]) -> Result<()> {
        let mut out = self.output_data.write().unwrap_or_else(|e| e.into_inner());
        if data.len() != out.len() {
            return Err(Error::msg(format!("output size mismatch: got {}, want {}", data.len(), out.len())));
        }
        out.copy_from_slice(data);
        Ok(())
    }

    /// Returns a copy of the current Originator-to-Target assembly data.
    pub fn output(&self) -> Vec<u8> {
        self.output_data.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Returns a copy of the most recently received Target-to-Originator assembly data.
    pub fn input(&self) -> Vec<u8> {
        self.input_data.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Returns the time elapsed since the last T-O packet was received.
    pub fn input_age(&self) -> Duration {
        lock(&self.last_receive).elapsed()
    }

    // Ref: CIP Vol. 1, Forward_Open Connection Timeout Multiplier: the connection times out
    // after RPI * 4 << multiplier without data (section unverified).
    /// True if no T-O packet has been received within the CIP connection watchdog timeout,
    /// RPI * (4 << timeout_multiplier).
    pub fn is_timed_out(&self) -> bool {
        // Deviation: Go's shift/multiplication silently overflow for huge multipliers; here
        // they saturate instead of panicking.
        let mult = 4u64.checked_shl(self.timeout_mult as u32).filter(|m| m >> self.timeout_mult as u32 == 4);
        let timeout = match mult {
            Some(m) => u32::try_from(m).ok().and_then(|m| self.rpi.checked_mul(m)).unwrap_or(Duration::MAX),
            None => Duration::MAX,
        };
        self.input_age() > timeout
    }

    // Implementation detail: Go `produceLoop` (a ticker goroutine). Sends the output assembly
    // at the negotiated RPI until the connection or the scanner is stopped.
    fn produce_loop(&self, shared: &Shared) {
        // Go's time.NewTicker panics for a non-positive period; clamp instead.
        let period = self.rpi.max(Duration::from_millis(1));
        let mut next = Instant::now() + period;
        loop {
            // Wait until `next`, waking early when stopped.
            loop {
                if shared.done.load(Ordering::SeqCst) {
                    return;
                }
                let guard = lock(&self.stop.0);
                if *guard {
                    return;
                }
                let now = Instant::now();
                if now >= next {
                    break;
                }
                let wait = (next - now).min(POLL_INTERVAL);
                let (g, _) = self.stop.1.wait_timeout(guard, wait).unwrap_or_else(|e| e.into_inner());
                if *g {
                    return;
                }
            }
            if self.is_stopped() || shared.done.load(Ordering::SeqCst) {
                return;
            }
            self.send_packet(&shared.udp);
            next += period;
            // Ticker semantics: drop missed ticks rather than bursting.
            let now = Instant::now();
            if next < now {
                next = now + period;
            }
        }
    }

    // Ref: CIP Vol. 2, Common Packet Format (section unverified) with Sequenced Address item
    // (0x8002, 8 bytes: O->T connection ID + 32-bit sequence number) and Connected Data item
    // (0x00B1: 16-bit sequence count, optional 32-bit run/idle header, assembly data) (I/O
    // framing section unverified).
    // Builds the CPF packet manually (same format as runtime/scheduler.go) and sends it.
    fn send_packet(&self, udp: &UdpSocket) {
        let snapshot = self.output();

        let seq = self.sequence_count.fetch_add(1, Ordering::SeqCst).wrapping_add(1);

        let mut data_len = 2 + snapshot.len(); // seq count + assembly
        if self.run_idle_header {
            data_len += 4;
        }

        let mut pkt = Vec::with_capacity(18 + data_len);
        // Item count = 2
        pkt.extend_from_slice(&2u16.to_le_bytes());
        // Item 1: Sequenced Address (0x8002), length 8
        pkt.extend_from_slice(&ITEM_ID_SEQUENCED_ADDRESS.to_le_bytes());
        pkt.extend_from_slice(&8u16.to_le_bytes());
        pkt.extend_from_slice(&self.ot_connection_id.to_le_bytes());
        pkt.extend_from_slice(&(seq as u32).to_le_bytes());
        // Item 2: Connected Data (0x00B1), length = data_len (Go truncates to uint16)
        pkt.extend_from_slice(&ITEM_ID_CONNECTED_DATA.to_le_bytes());
        pkt.extend_from_slice(&(data_len as u16).to_le_bytes());

        pkt.extend_from_slice(&seq.to_le_bytes());
        if self.run_idle_header {
            // Ref: CIP Vol. 2, run/idle header bit 0 = Run (section unverified).
            pkt.extend_from_slice(&1u32.to_le_bytes()); // Run mode
        }
        pkt.extend_from_slice(&snapshot);

        if let Some(addr) = self.remote_addr {
            let _ = udp.send_to(&pkt, addr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cip::MessageRouter;
    use crate::objects::assembly::AssemblyObject;
    use crate::objects::connmgr::ConnectionManager;
    use crate::session::fixture::FakeTarget;
    use crate::conn::TcpConn;
    use std::collections::HashSet;

    // Implementation detail: Go constructs `IOConn{...}` literals in tests; this mirrors that.
    fn bare_conn(out: usize, inp: usize, rpi: Duration, mult: u8) -> IoConn {
        IoConn {
            ot_connection_id: 0,
            to_connection_id: 0,
            connection_serial_number: 0,
            vendor_id: 0,
            originator_serial_number: 0,
            output_data: RwLock::new(vec![0; out]),
            input_data: RwLock::new(vec![0; inp]),
            rpi,
            sequence_count: AtomicU16::new(0),
            last_receive: Mutex::new(Instant::now()),
            timeout_mult: mult,
            run_idle_header: false,
            remote_addr: None,
            stop: (Mutex::new(false), Condvar::new()),
        }
    }

    // Implementation detail: stands in for the Go `NewServer(router, WithServerConn(pipe))` +
    // `NewTCPConn` + `NewSession` + `Register` fixture, over a loopback TCP fake target.
    fn setup_session(router: Arc<MessageRouter>) -> (FakeTarget, Arc<Session>) {
        let target = FakeTarget::start(router);
        let tc = TcpConn::new(&target.addr, &[]).expect("NewTCPConn");
        let sess = Arc::new(Session::new(tc, None));
        sess.register(&Context::background()).expect("Register");
        (target, sess)
    }

    // ===========================================================================
    // Test 1: ForwardOpenRequest encode round-trip
    // ===========================================================================

    #[test]
    fn forward_open_request_encode() {
        let mut conn_path = Path::new();
        conn_path.add_class(cip::CLASS_ASSEMBLY);
        conn_path.add_instance(100);
        conn_path.add_class(cip::CLASS_ASSEMBLY);
        conn_path.add_instance(101);

        let original = ForwardOpenRequest {
            priority_time_tick: 0x0A,
            timeout_ticks: 0xF0,
            ot_connection_id: 0x1234,
            to_connection_id: 0,
            connection_serial_number: 0x0001,
            vendor_id: 0x0042,
            originator_serial_number: 0xABCD,
            connection_timeout_multiplier: 3,
            ot_rpi: 10000,
            ot_network_connection_params: 0x43F4,
            to_rpi: 10000,
            to_network_connection_params: 0x43F4,
            transport_type_trigger: 0x01,
            connection_path: conn_path.bytes().to_vec(),
            ..Default::default()
        };

        let encoded = original.encode().expect("encode");

        // Manually verify key fields from the encoded bytes.
        let b = &encoded;
        assert_eq!(b[0], 0x0A, "PriorityTimeTick");
        assert_eq!(b[1], 0xF0, "TimeoutTicks");
        assert_eq!(u32::from_le_bytes(b[2..6].try_into().unwrap()), 0x1234, "OTConnectionID");
        assert_eq!(u32::from_le_bytes(b[6..10].try_into().unwrap()), 0, "TOConnectionID");
        assert_eq!(u16::from_le_bytes(b[10..12].try_into().unwrap()), 0x0001, "ConnectionSerialNumber");
        assert_eq!(u16::from_le_bytes(b[12..14].try_into().unwrap()), 0x0042, "VendorID");
        assert_eq!(u32::from_le_bytes(b[14..18].try_into().unwrap()), 0xABCD, "OriginatorSerialNumber");
    }

    // ===========================================================================
    // Test 2: IOScanner Open/Close lifecycle
    // ===========================================================================

    #[test]
    fn io_scanner_open_close() {
        let ao = AssemblyObject::new();
        ao.register_assembly(100, vec![0; 8]); // consume
        ao.register_assembly(101, vec![0; 8]); // produce

        let open_called = Arc::new(AtomicBool::new(false));
        let close_called = Arc::new(AtomicBool::new(false));
        let (oc, cc) = (open_called.clone(), close_called.clone());

        let cm = ConnectionManager::new()
            .with_on_open(move |_c, _req| oc.store(true, Ordering::SeqCst))
            .with_on_close(move |_c| cc.store(true, Ordering::SeqCst));

        let router = Arc::new(MessageRouter::new());
        router.register_object(cip::CLASS_CONNECTION_MGR, Arc::new(cm));

        let (_target, sess) = setup_session(router);
        let ctx = Context::background();

        let scanner = IoScanner::new(sess, "127.0.0.1:0", &[]).expect("NewIOScanner");

        let cfg = IoConnectionConfig {
            ot_connection_point: 100,
            to_connection_point: 101,
            ot_size: 8,
            to_size: 8,
            rpi: Duration::from_millis(10),
            timeout_multiplier: 3,
            target_addr: Some("127.0.0.1:9999".parse().unwrap()), // dummy
            ..Default::default()
        };

        let conn = scanner.open(&ctx, &cfg).expect("Open");

        assert_ne!(conn.ot_connection_id, 0, "OTConnectionID should not be 0");
        assert_ne!(conn.to_connection_id, 0, "TOConnectionID should not be 0");
        assert!(open_called.load(Ordering::SeqCst), "OnOpen callback not fired");

        scanner.close(&ctx, &conn).expect("Close");
        assert!(close_called.load(Ordering::SeqCst), "OnClose callback not fired");

        let _ = scanner.shutdown(&ctx);
    }

    // ===========================================================================
    // Test 3: Full bidirectional I/O exchange
    // ===========================================================================

    // Implementation detail: the Go test uses the `runtime` package (UDP runtime + scheduler) as
    // the target-side I/O engine. To keep this test independent of that module, a minimal
    // in-test UDP target does the same job: it consumes O->T packets addressed to the O->T
    // connection ID into assembly 100 and cyclically produces assembly 101 to the scanner on
    // the T->O connection ID.
    struct MiniTarget {
        stop: Arc<AtomicBool>,
        threads: Vec<JoinHandle<()>>,
        addr: SocketAddr,
        // Scanner UDP address to produce to (Go `rt.SetProducerAddr`).
        producer_addr: Arc<Mutex<Option<SocketAddr>>>,
        // (OT connection ID, TO connection ID, RPI) registered from the OnOpen callback.
        conns: Arc<Mutex<Vec<(u32, u32, Duration)>>>,
    }

    impl MiniTarget {
        fn start(ao: Arc<AssemblyObject>) -> MiniTarget {
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            sock.set_read_timeout(Some(Duration::from_millis(10))).unwrap();
            let addr = sock.local_addr().unwrap();
            let sock = Arc::new(sock);
            let stop = Arc::new(AtomicBool::new(false));
            let producer_addr = Arc::new(Mutex::new(None));
            let conns: Arc<Mutex<Vec<(u32, u32, Duration)>>> = Arc::new(Mutex::new(Vec::new()));
            let mut threads = Vec::new();

            // Consumer: parse CPF, write payload into assembly 100.
            {
                let (sock, stop, conns, ao) = (sock.clone(), stop.clone(), conns.clone(), ao.clone());
                threads.push(std::thread::spawn(move || {
                    let mut buf = [0u8; 2048];
                    while !stop.load(Ordering::SeqCst) {
                        let Ok((n, _)) = sock.recv_from(&mut buf) else { continue };
                        let d = &buf[..n];
                        let Some((id, p)) = parse_io_packet(d) else { continue };
                        if p.len() < 2 || !lock(&conns).iter().any(|c| c.0 == id) {
                            continue;
                        }
                        let _ = ao.set_attribute_single(100, 3, &p[2..]);
                    }
                }));
            }
            // Producer: send assembly 101 every RPI once a producer address is known.
            {
                let (sock, stop, conns, ao, pa) = (sock, stop.clone(), conns.clone(), ao, producer_addr.clone());
                threads.push(std::thread::spawn(move || {
                    let mut seq = 0u16;
                    while !stop.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(10));
                        let Some(dst) = *lock(&pa) else { continue };
                        let Some(&(_, to_id, _)) = lock(&conns).first() else { continue };
                        let Ok(data) = ao.get_attribute_single(101, 3) else { continue };
                        seq = seq.wrapping_add(1);
                        let mut pkt = Vec::new();
                        pkt.extend_from_slice(&2u16.to_le_bytes());
                        pkt.extend_from_slice(&ITEM_ID_SEQUENCED_ADDRESS.to_le_bytes());
                        pkt.extend_from_slice(&8u16.to_le_bytes());
                        pkt.extend_from_slice(&to_id.to_le_bytes());
                        pkt.extend_from_slice(&(seq as u32).to_le_bytes());
                        pkt.extend_from_slice(&ITEM_ID_CONNECTED_DATA.to_le_bytes());
                        pkt.extend_from_slice(&((2 + data.len()) as u16).to_le_bytes());
                        pkt.extend_from_slice(&seq.to_le_bytes());
                        pkt.extend_from_slice(&data);
                        let _ = sock.send_to(&pkt, dst);
                    }
                }));
            }
            MiniTarget { stop, threads, addr, producer_addr, conns }
        }
    }

    impl Drop for MiniTarget {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            for h in self.threads.drain(..) {
                let _ = h.join();
            }
        }
    }

    #[test]
    fn io_bidirectional_exchange() {
        let ao = Arc::new(AssemblyObject::new());
        ao.register_assembly(100, vec![0; 4]); // consume (scanner sends here)
        ao.register_assembly(101, vec![0; 4]); // produce (server sends from here)

        let rt = MiniTarget::start(ao.clone());
        let runtime_addr = rt.addr;

        let (conns_open, conns_close) = (rt.conns.clone(), rt.conns.clone());
        let cm = ConnectionManager::new()
            .with_on_open(move |c, req| {
                let rpi = Duration::from_micros(req.ot_rpi as u64);
                lock(&conns_open).push((c.ot_connection_id, c.to_connection_id, rpi));
            })
            .with_on_close(move |c| {
                lock(&conns_close).retain(|x| x.0 != c.ot_connection_id);
            });

        let router = Arc::new(MessageRouter::new());
        router.register_object(cip::CLASS_CONNECTION_MGR, Arc::new(cm));

        let (_target, sess) = setup_session(router);
        let ctx = Context::background();

        let scanner = IoScanner::new(sess, "127.0.0.1:0", &[]).expect("NewIOScanner");

        let cfg = IoConnectionConfig {
            ot_connection_point: 100,
            to_connection_point: 101,
            ot_size: 4,
            to_size: 4,
            rpi: Duration::from_millis(10),
            timeout_multiplier: 3,
            target_addr: Some(runtime_addr),
            ..Default::default()
        };

        let io_conn = scanner.open(&ctx, &cfg).expect("Open");

        // --- Scanner -> Server (O->T) ---
        let output_data = [0xDE, 0xAD, 0xBE, 0xEF];
        io_conn.set_output(&output_data).expect("SetOutput");

        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if let Ok(data) = ao.get_attribute_single(100, 3)
                && data == output_data {
                    break;
                }
            std::thread::sleep(Duration::from_millis(5));
        }

        let consumed = ao.get_attribute_single(100, 3).expect("read consume assembly");
        assert_eq!(consumed, output_data, "O->T: server received {consumed:X?}, want {output_data:X?}");

        // --- Server -> Scanner (T->O) ---
        let produce_data = [0xCA, 0xFE, 0xBA, 0xBE];
        ao.set_attribute_single(101, 3, &produce_data).expect("write produce assembly");

        // The target needs the producer's remote address: the scanner's UDP address.
        *lock(&rt.producer_addr) = Some(scanner.local_addr().unwrap());

        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if io_conn.input() == produce_data {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }

        let input = io_conn.input();
        assert_eq!(input, produce_data, "T->O: scanner received {input:X?}, want {produce_data:X?}");

        // --- Clean shutdown ---
        scanner.close(&ctx, &io_conn).expect("Close");
        let _ = scanner.shutdown(&ctx);
    }

    // ===========================================================================
    // Test 4: Watchdog timeout detection
    // ===========================================================================

    #[test]
    fn io_conn_timeout() {
        // timeout = 10ms * 4 = 40ms
        let conn = bare_conn(0, 4, Duration::from_millis(10), 0);
        // Set last receive to the past.
        *lock(&conn.last_receive) = Instant::now() - Duration::from_millis(100);
        assert!(conn.is_timed_out(), "expected IsTimedOut() = true");

        // Set last receive to now.
        *lock(&conn.last_receive) = Instant::now();
        assert!(!conn.is_timed_out(), "expected IsTimedOut() = false after fresh receive");
    }

    // ===========================================================================
    // Test 5: SetOutput size validation
    // ===========================================================================

    #[test]
    fn io_conn_set_output_size_validation() {
        let conn = bare_conn(4, 0, Duration::ZERO, 0);

        conn.set_output(&[1, 2, 3, 4]).expect("SetOutput correct size");
        assert!(conn.set_output(&[1, 2]).is_err(), "expected error for wrong size");
        assert_eq!(conn.set_output(&[1, 2]).unwrap_err().to_string(), "output size mismatch: got 2, want 4");
    }

    // ===========================================================================
    // Test 6: Multiple connections shutdown
    // ===========================================================================

    #[test]
    fn io_scanner_multiple_connections() {
        let cm = ConnectionManager::new();
        let router = Arc::new(MessageRouter::new());
        router.register_object(cip::CLASS_CONNECTION_MGR, Arc::new(cm));

        let (_target, sess) = setup_session(router);
        let ctx = Context::background();

        let scanner = IoScanner::new(sess, "127.0.0.1:0", &[]).expect("NewIOScanner");

        // Open 5 connections.
        let mut conns = Vec::new();
        for i in 0..5u16 {
            let c = scanner
                .open(
                    &ctx,
                    &IoConnectionConfig {
                        ot_connection_point: 100 + i,
                        to_connection_point: 200 + i,
                        ot_size: 4,
                        to_size: 4,
                        rpi: Duration::from_millis(50),
                        timeout_multiplier: 3,
                        target_addr: Some("127.0.0.1:9999".parse().unwrap()),
                        ..Default::default()
                    },
                )
                .unwrap_or_else(|e| panic!("Open connection {i}: {e}"));
            conns.push(c);
        }

        // Verify all have unique IDs.
        let mut seen = HashSet::new();
        for c in &conns {
            assert!(seen.insert(c.to_connection_id), "duplicate TOConnectionID: 0x{:08X}", c.to_connection_id);
        }

        // Shutdown should close all and not hang.
        let (tx, rx) = std::sync::mpsc::channel();
        let sc = Arc::new(scanner);
        let sc2 = sc.clone();
        std::thread::spawn(move || {
            let _ = sc2.shutdown(&Context::background());
            let _ = tx.send(());
        });
        rx.recv_timeout(Duration::from_secs(5)).expect("Shutdown timed out");
    }

    // ---- additional tests (not in Go) ----

    #[test]
    fn incoming_packet_validation_and_run_idle() {
        let (ao_router, _) = (Arc::new(MessageRouter::new()), ());
        let (_t, sess) = setup_session(ao_router);
        let scanner = IoScanner::new(sess, "127.0.0.1:0", &[]).unwrap();
        let mut c = bare_conn(0, 2, Duration::from_millis(10), 0);
        c.to_connection_id = 7;
        c.run_idle_header = true;
        let c = Arc::new(c);
        scanner.shared.connections.write().unwrap().insert(7, c.clone());

        let pkt = |id: u32, body: &[u8]| {
            let mut p = Vec::new();
            p.extend_from_slice(&2u16.to_le_bytes());
            p.extend_from_slice(&ITEM_ID_SEQUENCED_ADDRESS.to_le_bytes());
            p.extend_from_slice(&8u16.to_le_bytes());
            p.extend_from_slice(&id.to_le_bytes());
            p.extend_from_slice(&0u32.to_le_bytes());
            p.extend_from_slice(&ITEM_ID_CONNECTED_DATA.to_le_bytes());
            p.extend_from_slice(&(body.len() as u16).to_le_bytes());
            p.extend_from_slice(body);
            p
        };
        // seq(2) + run/idle(4) + 2 data bytes
        scanner.shared.handle_incoming_packet(&pkt(7, &[1, 0, 1, 0, 0, 0, 0xAA, 0xBB]));
        assert_eq!(c.input(), vec![0xAA, 0xBB]);
        // wrong size: ignored; unknown id: ignored; truncated: ignored; short: ignored
        scanner.shared.handle_incoming_packet(&pkt(7, &[1, 0, 1, 0, 0, 0, 1, 2, 3]));
        scanner.shared.handle_incoming_packet(&pkt(8, &[1, 0, 1, 0, 0, 0, 9, 9]));
        let mut trunc = pkt(7, &[1, 0, 1, 0, 0, 0, 9, 9]);
        trunc.truncate(trunc.len() - 1);
        scanner.shared.handle_incoming_packet(&trunc);
        scanner.shared.handle_incoming_packet(&[0u8; 5]);
        assert_eq!(c.input(), vec![0xAA, 0xBB]);
    }

    #[test]
    fn timeout_multiplier_overflow_does_not_panic() {
        let conn = bare_conn(0, 0, Duration::from_millis(10), 255);
        assert!(!conn.is_timed_out());
    }
}
