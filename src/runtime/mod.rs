//! UDP-based implicit (cyclic) I/O messaging runtime for EtherNet/IP.
//!
//! Port of Go `runtime/runtime.go`.
//!
//! Ref: ODVA EtherNet/IP Adaptation of CIP (CIP Vol. 2), Chapter 3 "Encapsulation"/implicit
//! I/O messaging over UDP port 2222 (section unverified); CIP Vol. 1, Chapter 3 Connection
//! Management and Transport Class 1 (section unverified).
//!
//! Typical usage: create an `AssemblyObject`, create a [`Runtime`] and `start` it, call
//! `add_connection` after a successful Forward_Open, create a [`Scheduler`] and `start` it,
//! `remove_connection` on Forward_Close, then stop both.

pub mod scheduler;

pub use scheduler::Scheduler;

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::eip::{ITEM_ID_CONNECTED_ADDRESS, ITEM_ID_SEQUENCED_ADDRESS};
use crate::objects::assembly::{AssemblyInstance, AssemblyObject};

// Implementation detail (not spec): replaces Go's `chan struct{}` that is closed to signal
// a connection's goroutine to exit. Closing is idempotent and observable by waiters.
/// Close-once signal, the Rust stand-in for Go's `StopChan`.
#[derive(Debug, Default)]
pub struct StopSignal {
    closed: Mutex<bool>,
    cv: Condvar,
}

impl StopSignal {
    /// Creates an open signal.
    pub fn new() -> Arc<StopSignal> {
        Arc::new(StopSignal::default())
    }

    /// Closes the signal if not already closed (idempotent, like the Go select/close idiom).
    pub fn close(&self) {
        let mut g = self.closed.lock().unwrap_or_else(|e| e.into_inner());
        *g = true;
        self.cv.notify_all();
    }

    /// Reports whether the signal has been closed.
    pub fn is_closed(&self) -> bool {
        *self.closed.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Waits until closed or the timeout elapses; returns true if closed.
    pub fn wait_timeout(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut g = self.closed.lock().unwrap_or_else(|e| e.into_inner());
        while !*g {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            g = self
                .cv
                .wait_timeout(g, deadline - now)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        true
    }
}

// Ref: CIP Vol. 1, Chapter 3 Connection Management - connection parameters negotiated by
// Forward_Open (RPI, timeout multiplier, connection IDs) (section unverified); sequence count
// and Run/Idle header per Transport Class 1 / CIP Vol. 1 Real Time Format
// (section unverified).
/// A single cyclic I/O connection between a scanner and an adapter.
#[derive(Debug, Clone, Default)]
pub struct IOConnection {
    /// Connection ID (consuming ID for consumers, produced ID for producers).
    pub connection_id: u32,
    /// Requested Packet Interval.
    pub rpi: Duration,
    /// 16-bit sequence count for Class 1.
    pub sequence_count: u16,
    /// True if the 32-bit Run/Idle header is used.
    pub run_idle_header: bool,
    /// Remote UDP address that produced packets are sent to.
    pub remote_addr: Option<SocketAddr>,
    /// The assembly to consume/produce.
    pub assembly: Option<Arc<AssemblyInstance>>,
    /// Time the last packet was received.
    pub last_receive: Option<Instant>,
    /// Time the last packet was sent.
    pub last_send: Option<Instant>,
    /// Connection timeout multiplier (Forward_Open field).
    pub timeout_mult: u8,
    /// True if this side produces on this connection.
    pub is_producer: bool,
    /// True if this side consumes on this connection.
    pub is_consumer: bool,
    /// Closed when the connection is removed or times out.
    pub stop_chan: Option<Arc<StopSignal>>,
}

// Implementation detail (not spec): shared state between the public handle and threads.
pub(crate) struct Inner {
    pub(crate) connections: RwLock<HashMap<u32, IOConnection>>,
    pub(crate) socket: Mutex<Option<Arc<UdpSocket>>>,
    pub(crate) assembly_obj: Arc<AssemblyObject>,
    done: AtomicBool,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

// Implementation detail (not spec): Go's Runtime. Clones share state.
/// Receives implicit I/O UDP packets and dispatches them to assembly instances, with a
/// watchdog that removes timed-out consumer connections. Safe for concurrent use.
#[derive(Clone)]
pub struct Runtime {
    pub(crate) inner: Arc<Inner>,
}

impl Runtime {
    /// Creates a runtime backed by the given assembly object; not started until `start`.
    pub fn new(ao: Arc<AssemblyObject>) -> Runtime {
        Runtime {
            inner: Arc::new(Inner {
                connections: RwLock::new(HashMap::new()),
                socket: Mutex::new(None),
                assembly_obj: ao,
                done: AtomicBool::new(false),
                threads: Mutex::new(Vec::new()),
            }),
        }
    }

    // Implementation detail (not spec): binds the UDP socket and spawns listener and watchdog
    // threads. std cannot interrupt a blocking recv, so a short read timeout polls `done`.
    /// Begins listening for implicit I/O UDP packets on `address` (e.g. "0.0.0.0:2222").
    pub fn start(&self, address: &str) -> io::Result<()> {
        let addr = address
            .to_socket_addrs()
            .ok()
            .and_then(|mut a| a.next())
            .or_else(|| {
                // Go accepts ":2222" meaning all interfaces.
                address
                    .strip_prefix(':')
                    .and_then(|p| format!("0.0.0.0:{p}").parse().ok())
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("cannot resolve udp address {address:?}")))?;
        let sock = UdpSocket::bind(addr)?;
        sock.set_read_timeout(Some(Duration::from_millis(50)))?;
        let sock = Arc::new(sock);
        *self.inner.socket.lock().unwrap_or_else(|e| e.into_inner()) = Some(sock.clone());
        self.inner.done.store(false, Ordering::SeqCst);

        let r1 = self.clone();
        let l = std::thread::spawn(move || r1.listen_loop(sock));
        let r2 = self.clone();
        let w = std::thread::spawn(move || r2.watchdog_loop());
        let mut t = self.inner.threads.lock().unwrap_or_else(|e| e.into_inner());
        t.push(l);
        t.push(w);
        Ok(())
    }

    /// Registers an I/O connection; its `last_receive` is set to now.
    pub fn add_connection(&self, mut conn: IOConnection) {
        conn.last_receive = Some(Instant::now());
        self.inner
            .connections
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(conn.connection_id, conn);
    }

    /// Removes a connection and closes its stop signal. Unknown ids are ignored.
    pub fn remove_connection(&self, conn_id: u32) {
        let conn = self
            .inner
            .connections
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&conn_id);
        if let Some(c) = conn
            && let Some(s) = c.stop_chan {
                s.close();
            }
    }

    /// Local UDP address the runtime listens on, or `None` if not started.
    pub fn addr(&self) -> Option<SocketAddr> {
        self.inner
            .socket
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .and_then(|s| s.local_addr().ok())
    }

    /// Sets the remote UDP address for a producer connection.
    pub fn set_producer_addr(&self, conn_id: u32, addr: SocketAddr) {
        if let Some(c) = self
            .inner
            .connections
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(&conn_id)
        {
            c.remote_addr = Some(addr);
        }
    }

    /// Number of registered connections.
    pub fn connection_count(&self) -> usize {
        self.inner.connections.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Shuts the runtime down and joins the listener and watchdog threads. Idempotent.
    pub fn stop(&self) {
        self.inner.done.store(true, Ordering::SeqCst);
        let handles: Vec<_> = self
            .inner
            .threads
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
            .collect();
        for h in handles {
            let _ = h.join();
        }
    }

    // Implementation detail (not spec): 100 ms watchdog tick.
    fn watchdog_loop(&self) {
        let tick = Duration::from_millis(100);
        let mut next = Instant::now() + tick;
        while !self.inner.done.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(10));
            if Instant::now() >= next {
                next += tick;
                self.check_timeouts();
            }
        }
    }

    // Ref: CIP Vol. 1, Connection Timeout Multiplier - the connection times out after
    // RPI * 4 << multiplier (section unverified; Forward_Open "Connection Timeout Multiplier").
    fn check_timeouts(&self) {
        let mut map = self.inner.connections.write().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let mut expired = Vec::new();
        for (id, c) in map.iter() {
            if !c.is_consumer {
                continue;
            }
            // Go: `uint64(4) << TimeoutMult` (shift >= 64 gives 0), then RPI * mult.
            // Go's Duration multiply wraps; here overflow saturates to "never expires".
            let mult = 4u64.checked_shl(c.timeout_mult as u32).unwrap_or(0);
            let nanos = c.rpi.as_nanos().saturating_mul(u128::from(mult));
            let timeout = u64::try_from(nanos / 1_000_000_000)
                .ok()
                .map(|secs| Duration::new(secs, (nanos % 1_000_000_000) as u32))
                .unwrap_or(Duration::MAX);
            let last = c.last_receive.unwrap_or(now);
            if now.saturating_duration_since(last) > timeout {
                expired.push(*id);
            }
        }
        for id in expired {
            if let Some(c) = map.remove(&id)
                && let Some(s) = c.stop_chan {
                    s.close();
                }
        }
    }

    // Implementation detail (not spec): receive loop.
    fn listen_loop(&self, sock: Arc<UdpSocket>) {
        let mut buf = [0u8; 2048];
        while !self.inner.done.load(Ordering::SeqCst) {
            match sock.recv_from(&mut buf) {
                Ok((n, from)) => self.handle_packet(&buf[..n], from),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
                    ) => {}
                // Windows reports ICMP port-unreachable from a prior send_to as these; not fatal.
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused
                    ) => {}
                // Go returns on any other read error (implementation detail, not spec).
                Err(e) => {
                    eprintln!("rsethernetip runtime: listener stopped: {e}");
                    return;
                }
            }
        }
    }

    // Ref: CIP Vol. 2 Common Packet Format; implicit I/O packet = 2 items: Sequenced Address
    // Item (0x8002, 8 bytes: connection ID + sequence number) + Connected Data Item (0x00B1)
    // starting with a 16-bit sequence count (CIP Vol. 1 Transport Class 1, section unverified),
    // optionally followed by a 32-bit Run/Idle header. The Go-compatible Connected Address
    // Item (0x00A1, 4 bytes) is still accepted as a lenient fallback.
    fn handle_packet(&self, data: &[u8], _remote: SocketAddr) {
        if data.len() < 14 {
            return;
        }
        let u16_at = |o: usize| data.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
        let item_count = u16_at(0).unwrap_or(0);
        if item_count != 2 {
            return;
        }
        let len1 = u16_at(4).unwrap_or(0) as usize;
        let id1 = u16_at(2).unwrap_or(0);
        let ok = (id1 == ITEM_ID_SEQUENCED_ADDRESS && len1 == 8)
            || (id1 == ITEM_ID_CONNECTED_ADDRESS && len1 == 4);
        if !ok {
            return;
        }
        let conn_id = match data.get(6..10) {
            Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            None => return,
        };
        let hdr2 = 6 + len1;
        let len2 = match u16_at(hdr2 + 2) {
            Some(l) => l as usize,
            None => return,
        };
        let start = hdr2 + 4;
        let payload = match data.get(start..start + len2) {
            Some(p) => p,
            None => return,
        };

        let (run_idle, asm) = {
            let mut map = self.inner.connections.write().unwrap_or_else(|e| e.into_inner());
            let c = match map.get_mut(&conn_id) {
                Some(c) => c,
                None => return,
            };
            c.last_receive = Some(Instant::now());
            (c.run_idle_header, c.assembly.clone())
        };

        // Class 1 data always starts with a 2-byte sequence count.
        let mut off = 2;
        if payload.len() < off {
            return;
        }
        if run_idle {
            off += 4;
            if payload.len() < off {
                return;
            }
        }
        if let Some(a) = asm {
            // Assembly attribute 3 = Data.
            let _ = self.inner.assembly_obj.set_attribute_single(a.id, 3, &payload[off..]);
        }
    }
}

#[cfg(test)]
mod tests;
