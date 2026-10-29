//! Producer-side scheduler for implicit I/O. Port of Go `runtime/scheduler.go`.
//!
//! Ref: CIP Vol. 1, Chapter 3 Connection Management - Requested Packet Interval (RPI) cyclic
//! production (section unverified).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::Runtime;
use crate::eip::{ITEM_ID_CONNECTED_TRANSPORT, ITEM_ID_SEQUENCED_ADDRESS};

// Implementation detail (not spec): copy of the IOConnection fields needed to send a packet
// outside the connection lock.
struct ConnSnapshot {
    connection_id: u32,
    sequence_count: u16,
    run_idle_header: bool,
    remote_addr: Option<SocketAddr>,
    assembly_data: Vec<u8>,
}

// Implementation detail (not spec): Go's Scheduler (a goroutine with a 5 ms ticker).
/// Drives production of implicit I/O: every 5 ms it sends a UDP packet for each producer
/// connection whose RPI has elapsed. Clones share state.
#[derive(Clone)]
pub struct Scheduler {
    runtime: Runtime,
    stop: Arc<AtomicBool>,
    handle: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl Scheduler {
    /// Creates a scheduler bound to `r`; not started until `start`.
    pub fn new(r: &Runtime) -> Scheduler {
        Scheduler {
            runtime: r.clone(),
            stop: Arc::new(AtomicBool::new(false)),
            handle: Arc::new(Mutex::new(None)),
        }
    }

    /// Launches the scheduler thread.
    pub fn start(&self) {
        let s = self.clone();
        let h = std::thread::spawn(move || s.run());
        *self.handle.lock().unwrap_or_else(|e| e.into_inner()) = Some(h);
    }

    /// Signals the scheduler to exit and joins it. Safe to call multiple times.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let h = self.handle.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(h) = h {
            let _ = h.join();
        }
    }

    fn run(&self) {
        let tick = Duration::from_millis(5);
        let mut next = Instant::now() + tick;
        while !self.stop.load(Ordering::SeqCst) {
            let now = Instant::now();
            if now < next {
                std::thread::sleep(next - now);
                continue;
            }
            next += tick;
            if next < now {
                next = now + tick;
            }
            self.process_tick();
        }
    }

    // Checks all connections and sends data where the RPI has elapsed.
    fn process_tick(&self) {
        let now = Instant::now();
        let mut snaps = Vec::new();
        {
            let mut map = self
                .runtime
                .inner
                .connections
                .write()
                .unwrap_or_else(|e| e.into_inner());
            for c in map.values_mut() {
                if !c.is_producer {
                    continue;
                }
                if let Some(ls) = c.last_send
                    && now.saturating_duration_since(ls) < c.rpi {
                        continue;
                    }
                let asm = match &c.assembly {
                    Some(a) => a.clone(),
                    None => continue,
                };
                c.sequence_count = c.sequence_count.wrapping_add(1);
                c.last_send = Some(now);
                // Assembly attribute 3 = Data.
                let data = match self.runtime.inner.assembly_obj.get_attribute_single(asm.id, 3) {
                    Ok(d) => d,
                    Err(_) => continue,
                };
                snaps.push(ConnSnapshot {
                    connection_id: c.connection_id,
                    sequence_count: c.sequence_count,
                    run_idle_header: c.run_idle_header,
                    remote_addr: c.remote_addr,
                    assembly_data: data,
                });
            }
        }
        for s in &snaps {
            self.send_packet(s);
        }
    }

    // Ref: CIP Vol. 2 (EtherNet/IP Adaptation of CIP), Common Packet Format - Sequenced Address
    // Item (0x8002, 8 bytes: 32-bit connection ID + 32-bit encapsulation sequence number) +
    // Connected Data Item (0x00B1); data = 16-bit Class 1 sequence count, optional 32-bit
    // Run/Idle header (1 = run), then assembly data (section unverified). This deviates from
    // the Go original, which used the Connected Address Item (0x00A1).
    fn send_packet(&self, snap: &ConnSnapshot) {
        let addr = match snap.remote_addr {
            Some(a) => a,
            None => return,
        };
        let mut buf: Vec<u8> = Vec::with_capacity(16 + snap.assembly_data.len());
        buf.extend_from_slice(&2u16.to_le_bytes()); // item count
        buf.extend_from_slice(&ITEM_ID_SEQUENCED_ADDRESS.to_le_bytes());
        buf.extend_from_slice(&8u16.to_le_bytes());
        buf.extend_from_slice(&snap.connection_id.to_le_bytes());
        buf.extend_from_slice(&u32::from(snap.sequence_count).to_le_bytes());
        buf.extend_from_slice(&ITEM_ID_CONNECTED_TRANSPORT.to_le_bytes());
        let mut data_len = 2 + snap.assembly_data.len();
        if snap.run_idle_header {
            data_len += 4;
        }
        // Go truncates with uint16(); same here.
        buf.extend_from_slice(&(data_len as u16).to_le_bytes());
        buf.extend_from_slice(&snap.sequence_count.to_le_bytes());
        if snap.run_idle_header {
            buf.extend_from_slice(&1u32.to_le_bytes());
        }
        buf.extend_from_slice(&snap.assembly_data);
        // Go uses a fixed 2048-byte buffer; oversize payloads would panic there. Clamp.
        buf.truncate(2048);
        let sock = self
            .runtime
            .inner
            .socket
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(s) = sock {
            let _ = s.send_to(&buf, addr);
        }
    }
}
