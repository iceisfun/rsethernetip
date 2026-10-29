//! EtherNet/IP adapter (target): TCP listener, per-connection session handling and CIP
//! dispatch through a [`MessageRouter`]. Port of Go `server.go`.
//!
//! Implementation note (not spec): Go `net.Conn`/`net.Pipe` injection is replaced by
//! `std::net::TcpStream`/`TcpListener`; goroutines become OS threads which are joined on
//! [`Server::stop`].

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};

use crate::cip::{self, MessageRouter, STATUS_PATH_SEGMENT_ERROR};
use crate::eip::{self, Command, CommonPacketFormat, CpfItem, HEADER_SIZE};
use crate::logging::{Logger, NopLogger};
use crate::plc::Context;

// Implementation detail (not spec): the Go code rejects any encapsulated payload larger than
// 4096 bytes by dropping the connection.
const MAX_PACKET_SIZE: usize = 4096;

// Implementation detail (not spec): polling interval of the accept loop (std has no way to
// interrupt a blocking accept from another thread).
const ACCEPT_POLL: Duration = Duration::from_millis(5);

// Ref: CIP Vol. 2, Encapsulation Protocol, SendRRData and SendUnitData command-specific data:
// Interface Handle (UDINT) + Timeout (UINT) = 6 bytes (section unverified).
const SEND_DATA_PREFIX: usize = 6;

// Implementation detail (not spec): description of an active client connection as seen by the
// server (Go `ConnectedClient`).
/// Describes an active EtherNet/IP client connection as seen by the [`Server`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectedClient {
    pub remote_addr: String,
    /// Session handle assigned by RegisterSession (0 if none yet).
    pub session_handle: u32,
    pub connected_at: SystemTime,
}

// Implementation detail (not spec): connection callback type.
type ClientCallback = Arc<dyn Fn(ConnectedClient) + Send + Sync>;

// Implementation detail (not spec): per-connection tracking state (Go `connState`) plus a
// stream clone used by `stop` to unblock the handler thread.
struct ConnState {
    remote_addr: String,
    session_handle: u32,
    connected_at: SystemTime,
    stream: Option<TcpStream>,
}

// Implementation detail (not spec): server-internal error for a failed request. Any such error
// maps to encapsulation status STATUS_INVALID_COMMAND, as in Go.
#[derive(Debug)]
enum ServerError {
    Cip(cip::Error),
    CipLayer(cip::CipError),
    Eip(eip::Error),
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerError::Cip(e) => write!(f, "{e}"),
            ServerError::CipLayer(e) => write!(f, "{e}"),
            ServerError::Eip(e) => write!(f, "{e}"),
        }
    }
}

impl From<cip::Error> for ServerError {
    fn from(e: cip::Error) -> Self {
        ServerError::Cip(e)
    }
}
impl From<cip::CipError> for ServerError {
    fn from(e: cip::CipError) -> Self {
        ServerError::CipLayer(e)
    }
}
impl From<eip::Error> for ServerError {
    fn from(e: eip::Error) -> Self {
        ServerError::Eip(e)
    }
}

// Ref: CIP Vol. 1, Appendix B General Status Codes: 0x04 Path segment error (section
// unverified). Go's `errShortData` / `errNoCPFItem`.
fn err_short_data() -> ServerError {
    ServerError::Cip(cip::Error::new(STATUS_PATH_SEGMENT_ERROR))
}
fn err_no_cpf_item() -> ServerError {
    ServerError::Cip(cip::Error::new(STATUS_PATH_SEGMENT_ERROR))
}

// Implementation detail (not spec): shared server state; `Server` is a cheap clonable handle.
struct Inner {
    router: Arc<MessageRouter>,
    logger: Arc<dyn Logger>,
    listener: Mutex<Option<TcpListener>>,
    injected_conn: Mutex<Option<TcpStream>>,
    done: AtomicBool,
    // Session management: atomic counter ensures unique handles across connections.
    next_session: AtomicU32,
    next_conn_id: AtomicU64,
    // Implementation detail: accepted-but-not-finished connections (reserved at accept time).
    active: AtomicUsize,
    clients: Mutex<HashMap<u64, ConnState>>,
    on_connect: Option<ClientCallback>,
    on_disconnect: Option<ClientCallback>,
    // Maximum simultaneous client connections (0 = unlimited).
    max_clients: usize,
    identity: eip::ListIdentityItem,
    threads: Mutex<Vec<JoinHandle<()>>>,
    local_addr: Mutex<Option<std::net::SocketAddr>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// Ref: CIP Vol. 2, Chapter 2 Encapsulation Protocol: the adapter (target) side. Implements an
// EtherNet/IP adapter. It listens for TCP connections, handles session registration, and
// dispatches incoming CIP requests (SendRRData, SendUnitData) through a [`MessageRouter`].
/// EtherNet/IP adapter (target). Cloning yields another handle to the same server.
#[derive(Clone)]
pub struct Server {
    inner: Arc<Inner>,
}

// Implementation detail (not spec): builder replacing Go's functional `ServerOption`s.
/// Builder for [`Server`] (replaces Go's `ServerOption` values).
pub struct ServerBuilder {
    router: Arc<MessageRouter>,
    logger: Arc<dyn Logger>,
    listener: Option<TcpListener>,
    conn: Option<TcpStream>,
    identity: eip::ListIdentityItem,
    max_clients: usize,
    on_connect: Option<ClientCallback>,
    on_disconnect: Option<ClientCallback>,
}

impl ServerBuilder {
    /// Injects a pre-created listener (Go `WithServerListener`).
    pub fn listener(mut self, l: TcpListener) -> Self {
        self.listener = Some(l);
        self
    }

    /// Sets the logger (Go `WithServerLogger`).
    pub fn logger(mut self, l: Arc<dyn Logger>) -> Self {
        self.logger = l;
        self
    }

    /// Injects a single pre-established connection; `start` then skips the accept loop and
    /// handles only this connection (Go `WithServerConn`).
    pub fn conn(mut self, c: TcpStream) -> Self {
        self.conn = Some(c);
        self
    }

    // Ref: CIP Vol. 2, ListIdentity response (CIP Identity item) (section unverified).
    /// Configures the identity returned for ListIdentity (Go `WithIdentity`).
    pub fn identity(mut self, id: eip::ListIdentityItem) -> Self {
        self.identity = id;
        self
    }

    /// Sets the maximum simultaneous clients; extra connections are closed immediately.
    /// 0 (default) means unlimited (Go `WithMaxClients`).
    pub fn max_clients(mut self, max: usize) -> Self {
        self.max_clients = max;
        self
    }

    /// Callback fired when a client connection is accepted (Go `WithOnClientConnect`).
    pub fn on_client_connect(mut self, f: impl Fn(ConnectedClient) + Send + Sync + 'static) -> Self {
        self.on_connect = Some(Arc::new(f));
        self
    }

    /// Callback fired when a client disconnects (Go `WithOnClientDisconnect`).
    pub fn on_client_disconnect(mut self, f: impl Fn(ConnectedClient) + Send + Sync + 'static) -> Self {
        self.on_disconnect = Some(Arc::new(f));
        self
    }

    /// Builds the server.
    pub fn build(self) -> Server {
        Server {
            inner: Arc::new(Inner {
                router: self.router,
                logger: self.logger,
                listener: Mutex::new(self.listener),
                injected_conn: Mutex::new(self.conn),
                done: AtomicBool::new(false),
                next_session: AtomicU32::new(0),
                next_conn_id: AtomicU64::new(0),
                active: AtomicUsize::new(0),
                clients: Mutex::new(HashMap::new()),
                on_connect: self.on_connect,
                on_disconnect: self.on_disconnect,
                max_clients: self.max_clients,
                identity: self.identity,
                threads: Mutex::new(Vec::new()),
                local_addr: Mutex::new(None),
            }),
        }
    }
}

impl Server {
    // Implementation detail (not spec): default identity values mirror the Go defaults
    // (item type ListIdentity, encapsulation version 1).
    /// Starts building a server that dispatches CIP requests through `router`.
    pub fn builder(router: Arc<MessageRouter>) -> ServerBuilder {
        ServerBuilder {
            router,
            logger: Arc::new(NopLogger::new()),
            listener: None,
            conn: None,
            identity: eip::ListIdentityItem {
                type_id: eip::ITEM_ID_LIST_IDENTITY,
                encaps_version: 1,
                product_name: "GoIndustrial EIP Server".to_string(),
                ..Default::default()
            },
            max_clients: 0,
            on_connect: None,
            on_disconnect: None,
        }
    }

    /// Creates a server with default options (Go `NewServer(router)`).
    pub fn new(router: Arc<MessageRouter>) -> Server {
        Server::builder(router).build()
    }

    /// Address the server's listener is bound to, once started in listener mode.
    pub fn local_addr(&self) -> Option<std::net::SocketAddr> {
        *lock(&self.inner.local_addr)
    }

    // Implementation detail (not spec): `ctx` is accepted for API parity; like Go it is unused.
    /// Begins accepting connections. If a single connection was injected it is handled on a
    /// thread and this returns immediately. Otherwise the injected listener is used, or a TCP
    /// listener bound to `address` is created.
    pub fn start(&self, _ctx: &Context, address: &str) -> io::Result<()> {
        let inner = &self.inner;
        inner.done.store(false, Ordering::SeqCst);

        // Single injected connection mode.
        if let Some(conn) = lock(&inner.injected_conn).clone_conn()? {
            let srv = self.clone();
            let h = thread::spawn(move || srv.handle_conn(conn));
            lock(&inner.threads).push(h);
            return Ok(());
        }

        // Listener mode.
        let ln = {
            let mut g = lock(&inner.listener);
            if g.is_none() {
                *g = Some(TcpListener::bind(address)?);
            }
            match g.as_ref() {
                Some(l) => l.try_clone()?,
                None => return Err(io::Error::other("no listener")),
            }
        };
        ln.set_nonblocking(true)?;
        *lock(&inner.local_addr) = ln.local_addr().ok();

        let srv = self.clone();
        let h = thread::spawn(move || srv.accept_loop(ln));
        lock(&inner.threads).push(h);
        Ok(())
    }

    // Implementation detail (not spec): graceful stop. Closes the listener and all tracked
    // client connections so handler threads unblock, then joins every thread.
    /// Gracefully stops the server. Idempotent.
    pub fn stop(&self) -> io::Result<()> {
        let inner = &self.inner;
        if inner.done.swap(true, Ordering::SeqCst) {
            return Ok(()); // already stopped
        }

        // Drop the listener first to stop accepting new connections (the accept thread polls
        // `done` and drops its own clone).
        *lock(&inner.listener) = None;

        // Close all tracked client connections so handler threads unblock.
        for cs in lock(&inner.clients).values() {
            if let Some(s) = &cs.stream {
                let _ = s.shutdown(std::net::Shutdown::Both);
            }
        }
        // Also close the injected conn in case it was not yet tracked.
        if let Some(s) = lock(&inner.injected_conn).as_ref() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }

        // Join threads (a handler calling stop on itself would deadlock; skip own thread).
        let handles: Vec<JoinHandle<()>> = std::mem::take(&mut *lock(&inner.threads));
        let me = thread::current().id();
        for h in handles {
            if h.thread().id() != me {
                let _ = h.join();
            }
        }
        Ok(())
    }

    /// Returns a snapshot of all currently active client connections.
    pub fn connected_clients(&self) -> Vec<ConnectedClient> {
        lock(&self.inner.clients)
            .values()
            .map(|cs| ConnectedClient {
                remote_addr: cs.remote_addr.clone(),
                session_handle: cs.session_handle,
                connected_at: cs.connected_at,
            })
            .collect()
    }

    // Implementation detail (not spec): accept loop thread.
    fn accept_loop(&self, ln: TcpListener) {
        let inner = &self.inner;
        loop {
            if inner.done.load(Ordering::SeqCst) {
                return;
            }
            let (conn, peer) = match ln.accept() {
                Ok(c) => c,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::Interrupted => {
                    thread::sleep(ACCEPT_POLL);
                    continue;
                }
                Err(e) => {
                    if inner.done.load(Ordering::SeqCst) {
                        return;
                    }
                    inner.logger.error(format_args!("accept error: {}", e));
                    thread::sleep(ACCEPT_POLL);
                    continue;
                }
            };
            let _ = conn.set_nonblocking(false);
            let _ = conn.set_nodelay(true);

            // Enforce max-client limit (implementation detail, not spec). The slot is reserved
            // here, before spawning, via `active`, so back-to-back accepts cannot bypass it.
            let reserved = inner.active.fetch_add(1, Ordering::SeqCst) + 1;
            if inner.max_clients > 0
                && reserved > inner.max_clients {
                    inner.active.fetch_sub(1, Ordering::SeqCst);
                    inner.logger.warn(format_args!(
                        "max clients ({}) reached, rejecting {}",
                        inner.max_clients, peer
                    ));
                    let _ = conn.shutdown(std::net::Shutdown::Both);
                    continue;
                }

            let srv = self.clone();
            let h = thread::spawn(move || {
                srv.handle_conn(conn);
                srv.inner.active.fetch_sub(1, Ordering::SeqCst);
            });
            let mut threads = lock(&inner.threads);
            // Reap finished handler threads so the list stays bounded.
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
    }

    // Implementation detail (not spec): updates the tracked session handle of a connection.
    fn set_session(&self, id: u64, handle: u32) {
        if let Some(cs) = lock(&self.inner.clients).get_mut(&id) {
            cs.session_handle = handle;
        }
    }

    // Ref: CIP Vol. 2, Chapter 2 Encapsulation Protocol: command processing loop. Handles a
    // single EtherNet/IP TCP connection, processing encapsulation commands until the peer
    // disconnects or the server is stopped. Public so tests can call it directly.
    /// Handles a single EtherNet/IP TCP connection until the peer disconnects or the server
    /// is stopped. The connection is closed on return.
    pub fn handle_conn(&self, mut conn: TcpStream) {
        let inner = &self.inner;
        let remote_addr = conn.peer_addr().map(|a| a.to_string()).unwrap_or_default();
        let connected_at = SystemTime::now();
        let id = inner.next_conn_id.fetch_add(1, Ordering::SeqCst);

        lock(&inner.clients).insert(
            id,
            ConnState {
                remote_addr: remote_addr.clone(),
                session_handle: 0,
                connected_at,
                stream: conn.try_clone().ok(),
            },
        );

        if let Some(cb) = &inner.on_connect {
            cb(ConnectedClient { remote_addr: remote_addr.clone(), session_handle: 0, connected_at });
        }

        let mut session_handle: u32 = 0;
        self.conn_loop(&mut conn, id, &mut session_handle);
        let _ = conn.shutdown(std::net::Shutdown::Both);

        lock(&inner.clients).remove(&id);
        if let Some(cb) = &inner.on_disconnect {
            cb(ConnectedClient { remote_addr, session_handle, connected_at });
        }
    }

    // Implementation detail (not spec): the read/dispatch/respond loop.
    fn conn_loop(&self, conn: &mut TcpStream, id: u64, session_handle: &mut u32) {
        let inner = &self.inner;
        let mut header_buf = [0u8; HEADER_SIZE];

        loop {
            if inner.done.load(Ordering::SeqCst) {
                return;
            }

            // Read header: Ref: CIP Vol. 2, Encapsulation Protocol, header format (24 bytes) (section unverified).
            if conn.read_exact(&mut header_buf).is_err() {
                return;
            }
            let hdr = match eip::EncapsulationHeader::from_bytes(&header_buf) {
                Ok(h) => h,
                Err(_) => return,
            };
            let command = hdr.command;
            let data_len = hdr.length as usize;
            let mut session = hdr.session_handle;
            let sender_context = hdr.sender_context;

            if data_len > MAX_PACKET_SIZE {
                return;
            }

            // Bounded allocation: data_len <= MAX_PACKET_SIZE.
            let mut data = vec![0u8; data_len];
            if data_len > 0 && conn.read_exact(&mut data).is_err() {
                return;
            }

            let mut resp_data: Vec<u8> = Vec::new();
            let mut status: u32 = eip::STATUS_SUCCESS;

            // Ref: CIP Vol. 2, Encapsulation Protocol, encapsulation commands (section unverified).
            match command {
                // Ref: CIP Vol. 2, RegisterSession (0x0065): reply carries Protocol Version
                // (UINT) and Options Flags (UINT); the target assigns the Session Handle.
                // Ref: CIP Vol. 2, Encapsulation Protocol, RegisterSession request: Protocol
                // Version (UINT) + Options Flags (UINT) = 4 bytes; an unsupported version is
                // answered with status 0x0069, a wrong length with 0x0065 (section unverified).
                // A repeated RegisterSession on a connection is given a fresh handle, as in Go
                // (a Go test covers it).
                Command::REGISTER_SESSION if data.len() != 4 => {
                    status = eip::STATUS_INVALID_LENGTH;
                }
                Command::REGISTER_SESSION if u16::from_le_bytes([data[0], data[1]]) != 1 => {
                    status = eip::STATUS_UNSUPPORTED_PROTOCOL;
                    resp_data = vec![1, 0, 0, 0]; // supported version offered in the reply
                }
                Command::REGISTER_SESSION => {
                    let mut h = inner.next_session.fetch_add(1, Ordering::SeqCst).wrapping_add(1);
                    if h == 0 {
                        // Deviation from Go: never hand out the reserved "no session" handle 0.
                        h = inner.next_session.fetch_add(1, Ordering::SeqCst).wrapping_add(1);
                    }
                    *session_handle = h;
                    session = h;
                    self.set_session(id, h);
                    resp_data = vec![0u8; 4];
                    resp_data[0..2].copy_from_slice(&1u16.to_le_bytes()); // Protocol Version 1
                    resp_data[2..4].copy_from_slice(&0u16.to_le_bytes()); // Options 0
                }

                // Ref: CIP Vol. 2, UnRegisterSession (0x0066): no reply; connection closes.
                Command::UNREGISTER_SESSION => return,

                // Ref: CIP Vol. 2, ListIdentity (0x0063).
                Command::LIST_IDENTITY => match self.handle_list_identity() {
                    Ok(d) => resp_data = d,
                    Err(_) => status = eip::STATUS_INVALID_COMMAND,
                },

                // Ref: CIP Vol. 2, ListServices (0x0004).
                Command::LIST_SERVICES => match self.handle_list_services() {
                    Ok(d) => resp_data = d,
                    Err(_) => status = eip::STATUS_INVALID_COMMAND,
                },

                // Ref: CIP Vol. 2, SendRRData (0x006F): unconnected explicit messaging; the
                // session handle must match the registered one.
                Command::SEND_RR_DATA => {
                    if session != *session_handle || *session_handle == 0 {
                        status = eip::STATUS_INVALID_SESSION_HANDLE;
                    } else {
                        match self.handle_send_rr_data(&data) {
                            Ok(d) => resp_data = d,
                            Err(e) => {
                                inner.logger.debug(format_args!("SendRRData failed: {}", e));
                                status = eip::STATUS_INVALID_COMMAND;
                            }
                        }
                    }
                }

                // Ref: CIP Vol. 2, SendUnitData (0x0070): connected explicit messaging.
                Command::SEND_UNIT_DATA => {
                    if session != *session_handle || *session_handle == 0 {
                        status = eip::STATUS_INVALID_SESSION_HANDLE;
                    } else {
                        match self.handle_send_unit_data(&data) {
                            Ok(d) => resp_data = d,
                            Err(e) => {
                                inner.logger.debug(format_args!("SendUnitData failed: {}", e));
                                status = eip::STATUS_INVALID_COMMAND;
                            }
                        }
                    }
                }

                // Unsupported command: Ref: CIP Vol. 2, Encapsulation Protocol, encapsulation status
                // codes: 0x0001 invalid or unsupported command (section unverified).
                _ => status = eip::STATUS_INVALID_COMMAND,
            }

            // Send response: header echoes command and sender context.
            // Ref: CIP Vol. 2, Encapsulation Protocol, header format (section unverified).
            let resp_header = eip::EncapsulationHeader {
                command,
                length: resp_data.len() as u16,
                session_handle: session,
                status,
                sender_context,
                options: 0,
            };
            let mut out = resp_header.bytes();
            out.extend_from_slice(&resp_data);
            if conn.write_all(&out).is_err() {
                return;
            }
        }
    }

    // Ref: CIP Vol. 2, ListIdentity reply (CIP Identity item) (section unverified).
    fn handle_list_identity(&self) -> Result<Vec<u8>, ServerError> {
        Ok(eip::encode_list_identity_response(std::slice::from_ref(&self.inner.identity))?)
    }

    // Ref: CIP Vol. 2, ListServices reply, Communications service item; capability flag 0x0020
    // = supports CIP encapsulation via TCP (section unverified).
    fn handle_list_services(&self) -> Result<Vec<u8>, ServerError> {
        Ok(eip::encode_list_services_response(&[eip::ListServicesItem {
            type_id: eip::ITEM_ID_LIST_SERVICES,
            length: 0,
            version: 1,
            capability_flags: 0x0020, // Supports CIP encapsulation via TCP
            name: "Communications".to_string(),
        }])?)
    }

    // Ref: CIP Vol. 2, SendRRData: Interface Handle(UDINT)+Timeout(UINT) then a Common Packet
    // Format with Null Address item and Unconnected Data item (0x00B2) carrying the CIP
    // Message Router request.
    fn handle_send_rr_data(&self, data: &[u8]) -> Result<Vec<u8>, ServerError> {
        if data.len() < SEND_DATA_PREFIX {
            return Err(err_short_data());
        }

        let cpf = CommonPacketFormat::decode(&data[SEND_DATA_PREFIX..])?;

        let item = cpf
            .find_item_by_type(eip::ITEM_ID_UNCONNECTED_MESSAGE)
            .ok_or_else(err_no_cpf_item)?;

        let mr_req = cip::decode_message_router_request(&item.data)?;
        let mr_resp = self.inner.router.dispatch(&mr_req)?;
        let resp_bytes = mr_resp.encode()?;

        wrap_unconnected_response(&resp_bytes)
    }

    // Ref: CIP Vol. 2, SendUnitData: Connected Address item (0x00A1, connection ID) and
    // Connected Data item (0x00B1: sequence count UINT + CIP request).
    fn handle_send_unit_data(&self, data: &[u8]) -> Result<Vec<u8>, ServerError> {
        if data.len() < SEND_DATA_PREFIX {
            return Err(err_short_data());
        }

        let cpf = CommonPacketFormat::decode(&data[SEND_DATA_PREFIX..])?;

        let addr_item = match cpf.find_item_by_type(eip::ITEM_ID_CONNECTED_ADDRESS) {
            Some(i) if i.data.len() >= 4 => i,
            _ => return Err(err_no_cpf_item()),
        };
        let data_item = match cpf.find_item_by_type(eip::ITEM_ID_CONNECTED_DATA) {
            Some(i) if i.data.len() >= 2 => i,
            _ => return Err(err_no_cpf_item()),
        };

        let seq_count = u16::from_le_bytes([data_item.data[0], data_item.data[1]]);
        let pdu = &data_item.data[2..];

        let mr_req = cip::decode_message_router_request(pdu)?;
        let mr_resp = self.inner.router.dispatch(&mr_req)?;
        let resp_bytes = mr_resp.encode()?;

        wrap_connected_response(&addr_item.data, seq_count, &resp_bytes)
    }
}

// Implementation detail (not spec): lets `start` take the injected stream (cloned so `stop`
// can still shut it down).
trait CloneConn {
    fn clone_conn(&self) -> io::Result<Option<TcpStream>>;
}
impl CloneConn for MutexGuard<'_, Option<TcpStream>> {
    fn clone_conn(&self) -> io::Result<Option<TcpStream>> {
        match self.as_ref() {
            Some(s) => Ok(Some(s.try_clone()?)),
            None => Ok(None),
        }
    }
}

// Ref: CIP Vol. 2, SendRRData reply: Interface Handle + Timeout (6 zero bytes), then CPF with
// Null Address item and Unconnected Data item (0x00B2).
// Wraps MR response bytes in a SendRRData CPF envelope.
fn wrap_unconnected_response(mr_resp_bytes: &[u8]) -> Result<Vec<u8>, ServerError> {
    let resp_cpf = CommonPacketFormat::new(vec![
        CpfItem::new(eip::ITEM_ID_NULL_ADDRESS, Vec::new()),
        CpfItem::new(eip::ITEM_ID_UNCONNECTED_MESSAGE, mr_resp_bytes.to_vec()),
    ]);
    let cpf_data = resp_cpf.encode()?;
    let mut resp = vec![0u8; SEND_DATA_PREFIX];
    resp.extend_from_slice(&cpf_data);
    Ok(resp)
}

// Ref: CIP Vol. 2, SendUnitData reply: Interface Handle + Timeout, then CPF with the Connected
// Address item echoed and a Connected Data item (sequence count + MR response).
// Wraps MR response bytes in a SendUnitData CPF envelope.
fn wrap_connected_response(addr_data: &[u8], seq_count: u16, mr_resp_bytes: &[u8]) -> Result<Vec<u8>, ServerError> {
    let mut data_buf = Vec::with_capacity(2 + mr_resp_bytes.len());
    data_buf.extend_from_slice(&seq_count.to_le_bytes());
    data_buf.extend_from_slice(mr_resp_bytes);

    let resp_cpf = CommonPacketFormat::new(vec![
        CpfItem::new(eip::ITEM_ID_CONNECTED_ADDRESS, addr_data.to_vec()),
        CpfItem::new(eip::ITEM_ID_CONNECTED_DATA, data_buf),
    ]);
    let cpf_data = resp_cpf.encode()?;
    let mut resp = vec![0u8; SEND_DATA_PREFIX];
    resp.extend_from_slice(&cpf_data);
    Ok(resp)
}

#[cfg(test)]
mod tests;
