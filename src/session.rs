//! EtherNet/IP session: RegisterSession / UnregisterSession, SendRRData and
//! the discovery commands over one [`TcpConn`].
//!
//! Port of Go `session.go`.

use std::sync::{Arc, Mutex};

use crate::cip::{self, MessageRouterRequest, MessageRouterResponse};
use crate::conn::{Error, Result, TcpConn};
use crate::eip::{self, Command, CommonPacketFormat, CpfItem, RegisterSessionData, SessionHandle};
use crate::logging::{Logger, NopLogger};
use crate::plc::Context;

// Ref: CIP Vol. 2, Section 2-4 "Encapsulation Commands" (RegisterSession 0x65): the target
// returns a Session Handle that must be echoed in every subsequent request (section number from
// knowledge; verify).
// Implementation detail: all methods performing a send/receive exchange are serialized by an
// internal mutex, so a Session is safe for concurrent use from multiple threads.
/// A registered EtherNet/IP session over a TCP connection.
pub struct Session {
    conn: TcpConn,
    // Implementation detail: protects `handle` (Go `mu`).
    handle: Mutex<SessionHandle>,
    logger: Arc<dyn Logger>,
    // Implementation detail: serializes send/receive exchanges (Go `ioMu`).
    io_mu: Mutex<()>,
}

// Implementation detail: Go compares `*Session` pointers; identity equality lets transports
// detect which connection is stale.
impl PartialEq for Session {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self, other)
    }
}

impl Session {
    /// Creates a new unregistered Session on top of `conn`. Call
    /// [`Session::register`] to obtain a session handle. If `logger` is `None`
    /// a no-op logger is used.
    pub fn new(conn: TcpConn, logger: Option<Arc<dyn Logger>>) -> Session {
        Session {
            conn,
            handle: Mutex::new(0),
            logger: logger.unwrap_or_else(|| Arc::new(NopLogger::new())),
            io_mu: Mutex::new(()),
        }
    }

    // Implementation detail: lock helpers tolerating poisoning.
    fn io_lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.io_mu.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn handle(&self) -> SessionHandle {
        *self.handle.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Returns the session handle assigned by the target (0 before registration).
    pub fn session_handle(&self) -> SessionHandle {
        self.handle()
    }

    // Ref: CIP Vol. 2, Section 2-4 RegisterSession (0x65): data = Protocol Version (UINT, 1) +
    // Options Flags (UINT, 0); reply carries the Session Handle in the encapsulation header
    // (section number unverified).
    /// Sends RegisterSession and stores the returned session handle.
    pub fn register(&self, _ctx: &Context) -> Result<()> {
        let reg = RegisterSessionData::new();
        let data = reg.encode()?;

        let _g = self.io_lock();

        self.logger.info(format_args!("Sending RegisterSession command"));
        self.conn.send(Command::REGISTER_SESSION, &data, 0)?;

        let (header, _) = self.conn.receive()?;

        if header.status != eip::STATUS_SUCCESS {
            return Err(Error::msg(format!("register session failed with status: 0x{:08X}", header.status)));
        }

        *self.handle.lock().unwrap_or_else(|e| e.into_inner()) = header.session_handle;
        self.logger.info(format_args!("Session registered. Handle: 0x{:08X}", header.session_handle));

        Ok(())
    }

    // Ref: CIP Vol. 2, Section 2-4 UnregisterSession (0x66): no data, no reply; the target closes
    // the session (section number unverified).
    /// Sends UnregisterSession to release the session handle on the target.
    pub fn unregister(&self, _ctx: &Context) -> Result<()> {
        let handle = self.handle();
        self.logger.info(format_args!("Sending UnregisterSession command"));
        self.conn.send(Command::UNREGISTER_SESSION, &[], handle)
    }

    // Implementation detail: remote address of the underlying TCP connection.
    /// Returns the remote socket address of the session's TCP connection.
    pub fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.conn.peer_addr()
    }

    /// Closes the underlying TCP connection.
    pub fn close(&self) -> Result<()> {
        self.conn.close()
    }

    // Ref: CIP Vol. 2, Section 2-4 SendRRData (0x6F): Interface Handle (UDINT, 0 for CIP) +
    // Timeout (UINT) + Common Packet Format (Null Address item 0x0000 + Unconnected Data item
    // 0x00B2) (section numbers unverified).
    /// Sends a SendRRData command carrying an unconnected CIP message and returns the
    /// Unconnected Message item data from the response CPF.
    pub fn send_rr_data(&self, _ctx: &Context, request: &[u8]) -> Result<Vec<u8>> {
        // CPF: item 0 Null Address (length 0), item 1 Unconnected Data (length len(request)).
        let cpf = CommonPacketFormat::new(vec![
            CpfItem::new(eip::ITEM_ID_NULL_ADDRESS, Vec::new()),
            CpfItem::new(eip::ITEM_ID_UNCONNECTED_MESSAGE, request),
        ]);

        let cpf_data = cpf.encode()?;

        // Prepend Interface Handle (4 bytes, 0) and Timeout (2 bytes, 0).
        let mut rr_data = vec![0u8; 6];
        rr_data.extend_from_slice(&cpf_data);

        let handle = self.handle();

        let _g = self.io_lock();

        self.logger.debug(format_args!("Sending RRData (len={})", rr_data.len()));
        self.conn.send(Command::SEND_RR_DATA, &rr_data, handle)?;

        let (header, resp_data) = self.conn.receive()?;

        if header.status != eip::STATUS_SUCCESS {
            return Err(Error::msg(format!("RRData command failed with status: 0x{:08X}", header.status)));
        }

        // Response contains Interface Handle (4 bytes) and Timeout (2 bytes).
        if resp_data.len() < 6 {
            return Err(Error::msg("response data too short"));
        }

        let resp_cpf = CommonPacketFormat::decode(&resp_data[6..])
            .map_err(|e| Error::wrap("failed to decode CPF", e.into()))?;

        match resp_cpf.find_item_by_type(eip::ITEM_ID_UNCONNECTED_MESSAGE) {
            Some(item) => Ok(item.data.clone()),
            None => Err(Error::msg("response CPF missing Unconnected Message item")),
        }
    }

    // Ref: CIP Vol. 1, Message Router request/response (section unverified), carried per
    // CIP Vol. 2 SendRRData.
    /// Encodes a [`MessageRouterRequest`], sends it via [`Session::send_rr_data`], and decodes
    /// the Message Router response.
    pub fn send_cip_request(&self, ctx: &Context, req: &MessageRouterRequest) -> Result<MessageRouterResponse> {
        let req_bytes = req.encode()?;

        self.logger.trace(format_args!("Sending CIP Request ({} bytes)", req_bytes.len()));

        let resp_bytes = self.send_rr_data(ctx, &req_bytes)?;

        self.logger.trace(format_args!("Received CIP Response ({} bytes)", resp_bytes.len()));

        Ok(cip::decode_message_router_response(&resp_bytes)?)
    }

    // Ref: CIP Vol. 2, Section 2-4 ListIdentity (0x63) (section number unverified); the reply is a
    // CPF-style item list of CIP Identity items.
    /// Sends ListIdentity and returns the identity items reported by the target.
    pub fn list_identity(&self, _ctx: &Context) -> Result<Vec<eip::ListIdentityItem>> {
        let _g = self.io_lock();

        self.logger.info(format_args!("Sending ListIdentity command"));
        self.conn.send(Command::LIST_IDENTITY, &[], 0)?;

        let (header, resp_data) = self.conn.receive()?;

        if header.status != eip::STATUS_SUCCESS {
            return Err(Error::msg(format!("ListIdentity command failed with status: 0x{:08X}", header.status)));
        }

        self.logger.trace(format_args!("ListIdentity response ({} bytes)", resp_data.len()));
        Ok(eip::decode_list_identity_response(&resp_data)?)
    }

    // Ref: CIP Vol. 2, Section 2-4 ListServices (0x04) (section number unverified).
    /// Sends ListServices and returns the communication services supported by the target.
    pub fn list_services(&self, _ctx: &Context) -> Result<Vec<eip::ListServicesItem>> {
        let _g = self.io_lock();

        self.logger.info(format_args!("Sending ListServices command"));
        self.conn.send(Command::LIST_SERVICES, &[], 0)?;

        let (header, resp_data) = self.conn.receive()?;

        if header.status != eip::STATUS_SUCCESS {
            return Err(Error::msg(format!("ListServices command failed with status: 0x{:08X}", header.status)));
        }

        Ok(eip::decode_list_services_response(&resp_data)?)
    }
}

// Implementation detail (not spec): in-test fake EtherNet/IP target on loopback, standing in for
// the Go tests' `Server` + `net.Pipe` fixture (`setupPipePair`). Shared by the client-side tests.
#[cfg(test)]
pub(crate) mod fixture {
    use super::*;
    use crate::cip::{MessageRouter, Object};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
    use std::time::Duration;

    // Go `mockObject`: handle_func(service, path, data); default returns 01 02 03 04.
    pub struct MockObject {
        #[allow(clippy::type_complexity)]
        pub f: Option<Box<dyn Fn(u8, &cip::Path, &[u8]) -> cip::Result<Vec<u8>> + Send + Sync>>,
    }

    impl MockObject {
        pub fn new(f: impl Fn(u8, &cip::Path, &[u8]) -> cip::Result<Vec<u8>> + Send + Sync + 'static) -> Arc<MockObject> {
            Arc::new(MockObject { f: Some(Box::new(f)) })
        }
    }

    impl Object for MockObject {
        fn handle_request(&self, service: u8, path: &cip::Path, data: &[u8]) -> cip::Result<Vec<u8>> {
            match &self.f {
                Some(f) => f(service, path, data),
                None => Ok(vec![1, 2, 3, 4]),
            }
        }
    }

    // Implementation detail: answers a request itself, bypassing the router (None = dispatch
    // normally). Lets tests produce replies an `Object` cannot, such as status 0x1E with data.
    pub type RawResponder = Arc<dyn Fn(&cip::MessageRouterRequest) -> Option<MessageRouterResponse> + Send + Sync>;

    // Implementation detail: handle to a running fake target.
    pub struct FakeTarget {
        pub addr: String,
        stop: Arc<AtomicBool>,
        // Number of sockets accepted so far (reconnect assertions).
        pub accepted: Arc<AtomicUsize>,
        // When set, each connection is dropped after serving this many requests
        // (RegisterSession counts), simulating a link failure.
        pub drop_after: Arc<AtomicUsize>,
        // Number of encapsulation requests served.
        pub requests: Arc<AtomicUsize>,
    }

    impl FakeTarget {
        pub fn start(router: Arc<MessageRouter>) -> FakeTarget {
            Self::start_with(router, None)
        }

        pub fn start_with(router: Arc<MessageRouter>, raw: Option<RawResponder>) -> FakeTarget {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let addr = listener.local_addr().unwrap().to_string();
            listener.set_nonblocking(true).unwrap();
            let t = FakeTarget {
                addr,
                stop: Arc::new(AtomicBool::new(false)),
                accepted: Arc::new(AtomicUsize::new(0)),
                drop_after: Arc::new(AtomicUsize::new(usize::MAX)),
                requests: Arc::new(AtomicUsize::new(0)),
            };
            let (stop, accepted, drop_after, requests) =
                (t.stop.clone(), t.accepted.clone(), t.drop_after.clone(), t.requests.clone());
            let next_handle = Arc::new(AtomicU32::new(1));
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((s, _)) => {
                            accepted.fetch_add(1, Ordering::SeqCst);
                            let _ = s.set_nonblocking(false);
                            let (router, stop, nh, raw) = (router.clone(), stop.clone(), next_handle.clone(), raw.clone());
                            let (da, rq) = (drop_after.clone(), requests.clone());
                            std::thread::spawn(move || serve(s, router, raw, stop, nh, da, rq));
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5))
                        }
                        Err(_) => break,
                    }
                }
            });
            t
        }
    }

    impl Drop for FakeTarget {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
        }
    }

    fn read_full(s: &mut TcpStream, buf: &mut [u8]) -> bool {
        s.read_exact(buf).is_ok()
    }

    fn reply(s: &mut TcpStream, cmd: Command, handle: u32, status: u32, ctx: [u8; 8], data: &[u8]) -> bool {
        let h = eip::EncapsulationHeader {
            command: cmd,
            length: data.len() as u16,
            session_handle: handle,
            status,
            sender_context: ctx,
            options: 0,
        };
        s.write_all(&h.bytes()).is_ok() && (data.is_empty() || s.write_all(data).is_ok())
    }

    fn serve(
        mut s: TcpStream,
        router: Arc<MessageRouter>,
        raw: Option<RawResponder>,
        stop: Arc<AtomicBool>,
        next_handle: Arc<AtomicU32>,
        drop_after: Arc<AtomicUsize>,
        requests: Arc<AtomicUsize>,
    ) {
        let _ = s.set_read_timeout(Some(Duration::from_millis(200)));
        let mut served = 0usize;
        loop {
            if stop.load(Ordering::SeqCst) {
                return;
            }
            let mut hb = [0u8; eip::HEADER_SIZE];
            // Poll with a timeout so the stop flag is observed; a partial header is retried.
            match s.peek(&mut hb) {
                Ok(0) => return,
                Ok(n) if n < eip::HEADER_SIZE => continue,
                Ok(_) => {}
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => continue,
                Err(_) => return,
            }
            let _ = s.set_read_timeout(None);
            if !read_full(&mut s, &mut hb) {
                return;
            }
            let h = eip::EncapsulationHeader::from_bytes(&hb).unwrap();
            let mut data = vec![0u8; h.length as usize];
            if !read_full(&mut s, &mut data) {
                return;
            }
            let _ = s.set_read_timeout(Some(Duration::from_millis(200)));
            requests.fetch_add(1, Ordering::SeqCst);
            served += 1;
            if served > drop_after.load(Ordering::SeqCst) {
                return; // drop the connection without replying
            }
            let ok = match h.command {
                Command::REGISTER_SESSION => {
                    let handle = next_handle.fetch_add(1, Ordering::SeqCst);
                    reply(&mut s, h.command, handle, 0, h.sender_context, &data)
                }
                Command::UNREGISTER_SESSION => return,
                Command::SEND_RR_DATA => {
                    let out = (|| {
                        let cpf = CommonPacketFormat::decode(data.get(6..)?).ok()?;
                        let item = cpf.find_item_by_type(eip::ITEM_ID_UNCONNECTED_MESSAGE)?;
                        let req = cip::decode_message_router_request(&item.data).ok()?;
                        let resp = match raw.as_ref().and_then(|f| f(&req)).map(Ok).unwrap_or_else(|| router.dispatch(&req)) {
                            Ok(r) => r,
                            Err(e) => MessageRouterResponse {
                                service: req.service | 0x80,
                                general_status: e.status,
                                ..Default::default()
                            },
                        };
                        let body = resp.encode().ok()?;
                        let out_cpf = CommonPacketFormat::new(vec![
                            CpfItem::new(eip::ITEM_ID_NULL_ADDRESS, Vec::new()),
                            CpfItem::new(eip::ITEM_ID_UNCONNECTED_MESSAGE, body),
                        ])
                        .encode()
                        .ok()?;
                        let mut rr = vec![0u8; 6];
                        rr.extend_from_slice(&out_cpf);
                        Some(rr)
                    })();
                    match out {
                        Some(rr) => reply(&mut s, h.command, h.session_handle, 0, h.sender_context, &rr),
                        None => reply(&mut s, h.command, h.session_handle, eip::STATUS_INCORRECT_DATA, h.sender_context, &[]),
                    }
                }
                Command::LIST_IDENTITY => {
                    let item = eip::ListIdentityItem {
                        type_id: eip::ITEM_ID_LIST_IDENTITY,
                        encaps_version: 1,
                        vendor_id: 0x1234,
                        device_type: 0x0C,
                        product_code: 7,
                        revision: [1, 2],
                        status: 0x30,
                        serial_number: 0xDEAD_BEEF,
                        product_name: "FakeTarget".into(),
                        state: 3,
                        ..Default::default()
                    };
                    match eip::encode_list_identity_response(&[item]) {
                        Ok(d) => reply(&mut s, h.command, 0, 0, h.sender_context, &d),
                        Err(_) => return,
                    }
                }
                Command::LIST_SERVICES => {
                    let item = eip::ListServicesItem {
                        type_id: eip::ITEM_ID_LIST_SERVICES,
                        version: 1,
                        capability_flags: 0x0120,
                        name: "Communications".into(),
                        ..Default::default()
                    };
                    match eip::encode_list_services_response(&[item]) {
                        Ok(d) => reply(&mut s, h.command, 0, 0, h.sender_context, &d),
                        Err(_) => return,
                    }
                }
                _ => reply(&mut s, h.command, h.session_handle, eip::STATUS_INVALID_COMMAND, h.sender_context, &[]),
            };
            if !ok {
                return;
            }
        }
    }
}

// Implementation detail: ported tests from Go ethernetip_test.go (client/session side) and
// hexdump_test.go, run against the in-test fake target on loopback instead of Server + net.Pipe.
#[cfg(test)]
mod tests {
    use super::fixture::{FakeTarget, MockObject};
    use super::*;
    use crate::cip::{self, MessageRouter, MessageRouterRequest};
    use crate::options::{with_conn, with_hex_dump};
    use std::io::Write;
    use std::net::TcpStream;
    use std::sync::atomic::{AtomicI32, Ordering};

    // Go `bytes.Buffer` shared with the tracer.
    #[derive(Clone, Default)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);
    impl Write for SharedBuf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl SharedBuf {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    fn ctx() -> Context {
        Context::background().with_timeout(std::time::Duration::from_secs(5))
    }

    // Go `setupPipePair` + `NewTCPConn("", WithConn(clientConn))`.
    fn pair(router: Arc<MessageRouter>) -> (FakeTarget, TcpConn) {
        let t = FakeTarget::start(router);
        let s = TcpStream::connect(&t.addr).unwrap();
        let tc = TcpConn::new("", &[with_conn(s)]).unwrap();
        (t, tc)
    }

    // Go TestEIPSessionRegisterUnregister (client half): the target hands out a non-zero handle
    // and closes the connection after UnregisterSession.
    #[test]
    fn eip_session_register_unregister() {
        let (_t, tc) = pair(Arc::new(MessageRouter::new()));
        let sess = Session::new(tc, None);
        sess.register(&ctx()).unwrap();
        assert_ne!(sess.session_handle(), 0, "session handle must not be 0");
        sess.unregister(&ctx()).unwrap();
        // Connection should close: the next receive fails.
        assert!(sess.conn.receive().is_err());
    }

    // Go TestFullIntegration
    #[test]
    fn full_integration() {
        let router = Arc::new(MessageRouter::new());
        router.register_object(
            0x04,
            MockObject::new(|service, _p, _d| match service {
                cip::SERVICE_READ_TAG => {
                    // Return TypeDINT (0x00C4) + value 42
                    let mut resp = vec![0u8; 6];
                    resp[0..2].copy_from_slice(&cip::TYPE_DINT.0.to_le_bytes());
                    resp[2..6].copy_from_slice(&42u32.to_le_bytes());
                    Ok(resp)
                }
                cip::SERVICE_WRITE_TAG => Ok(vec![]),
                _ => Err(cip::Error::new(cip::STATUS_SERVICE_NOT_SUPPORTED).into()),
            }),
        );
        let (_t, tc) = pair(router);
        let sess = Session::new(tc, None);
        sess.register(&ctx()).unwrap();

        let mut read_path = cip::Path::new();
        read_path.add_class(0x04);
        read_path.add_instance(1);
        let req = MessageRouterRequest {
            service: cip::SERVICE_READ_TAG,
            request_path: read_path,
            request_data: vec![0x01, 0x00], // 1 element
        };
        let resp = sess.send_cip_request(&ctx(), &req).unwrap();
        assert!(resp.is_success(), "CIP response error: 0x{:02X}", resp.general_status);
        assert!(resp.response_data.len() >= 6);
        let type_code = u16::from_le_bytes([resp.response_data[0], resp.response_data[1]]);
        assert_eq!(cip::DataType(type_code), cip::TYPE_DINT);
        let value = u32::from_le_bytes(resp.response_data[2..6].try_into().unwrap());
        assert_eq!(value, 42);

        sess.unregister(&ctx()).unwrap();
        sess.close().unwrap();
    }

    // Go TestClientServerLoopback
    #[test]
    fn client_server_loopback() {
        let stored = Arc::new(AtomicI32::new(100));
        let st = stored.clone();
        let router = Arc::new(MessageRouter::new());
        router.register_object(
            0x04,
            MockObject::new(move |service, _p, data| match service {
                cip::SERVICE_READ_TAG => {
                    let mut resp = vec![0u8; 6];
                    resp[0..2].copy_from_slice(&cip::TYPE_DINT.0.to_le_bytes());
                    resp[2..6].copy_from_slice(&(st.load(Ordering::SeqCst) as u32).to_le_bytes());
                    Ok(resp)
                }
                cip::SERVICE_WRITE_TAG => {
                    if data.len() < 8 {
                        return Err(cip::Error::new(cip::STATUS_NOT_ENOUGH_DATA).into());
                    }
                    st.store(i32::from_le_bytes(data[4..8].try_into().unwrap()), Ordering::SeqCst);
                    Ok(vec![])
                }
                _ => Err(cip::Error::new(cip::STATUS_SERVICE_NOT_SUPPORTED).into()),
            }),
        );
        let (_t, tc) = pair(router);
        let sess = Session::new(tc, None);
        sess.register(&ctx()).unwrap();

        let read_req = MessageRouterRequest {
            service: cip::SERVICE_READ_TAG,
            request_path: cip::build_path(0x04, 1, 0),
            request_data: vec![0x01, 0x00],
        };
        let resp = sess.send_cip_request(&ctx(), &read_req).unwrap();
        assert!(resp.is_success(), "ReadTag failed: status 0x{:02X}", resp.general_status);
        assert!(resp.response_data.len() >= 6);
        assert_eq!(i32::from_le_bytes(resp.response_data[2..6].try_into().unwrap()), 100, "initial value");

        // Write a new value (42)
        let mut write_data = vec![0u8; 8];
        write_data[0..2].copy_from_slice(&cip::TYPE_DINT.0.to_le_bytes());
        write_data[2..4].copy_from_slice(&1u16.to_le_bytes());
        write_data[4..8].copy_from_slice(&42u32.to_le_bytes());
        let write_req = MessageRouterRequest {
            service: cip::SERVICE_WRITE_TAG,
            request_path: cip::build_path(0x04, 1, 0),
            request_data: write_data,
        };
        let resp = sess.send_cip_request(&ctx(), &write_req).unwrap();
        assert!(resp.is_success(), "WriteTag failed: status 0x{:02X}", resp.general_status);

        // Read back to verify
        let resp = sess.send_cip_request(&ctx(), &read_req).unwrap();
        assert!(resp.is_success());
        assert_eq!(i32::from_le_bytes(resp.response_data[2..6].try_into().unwrap()), 42, "value after write");

        let _ = sess.unregister(&ctx());
    }

    // Go TestListServicesCommand (decode side through Session::list_services)
    #[test]
    fn list_services_command() {
        let (_t, tc) = pair(Arc::new(MessageRouter::new()));
        let sess = Session::new(tc, None);
        sess.register(&ctx()).unwrap();
        let items = sess.list_services(&ctx()).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "Communications");
        assert_ne!(items[0].capability_flags & 0x0020, 0, "expected CIP encapsulation capability flag (0x0020)");
    }

    // Go TestListIdentityCommand (decode side through Session::list_identity)
    #[test]
    fn list_identity_command() {
        let (_t, tc) = pair(Arc::new(MessageRouter::new()));
        let sess = Session::new(tc, None);
        sess.register(&ctx()).unwrap();
        let items = sess.list_identity(&ctx()).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].vendor_id, 0x1234);
        assert_eq!(items[0].product_name, "FakeTarget");
    }

    // Error path: RegisterSession rejected by the target.
    #[test]
    fn register_failure_reports_status() {
        // A raw listener that answers RegisterSession with a non-zero status.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            use std::io::Read;
            let (mut s, _) = l.accept().unwrap();
            let mut buf = [0u8; 28];
            s.read_exact(&mut buf).unwrap();
            let h = eip::EncapsulationHeader {
                command: Command::REGISTER_SESSION,
                status: eip::STATUS_UNSUPPORTED_PROTOCOL,
                ..Default::default()
            };
            s.write_all(&h.bytes()).unwrap();
        });
        let tc = TcpConn::new(&addr.to_string(), &[]).unwrap();
        let sess = Session::new(tc, None);
        let e = sess.register(&ctx()).unwrap_err();
        assert_eq!(e.to_string(), "register session failed with status: 0x00000069");
    }

    // ---------------- hexdump_test.go ----------------

    // Go TestHexDumpEIPRegisterSession
    #[test]
    fn hexdump_eip_register_session() {
        let (_t, clientconn) = (FakeTarget::start(Arc::new(MessageRouter::new())), ());
        let _ = clientconn;
        let t = _t;
        let buf = SharedBuf::default();
        let s = TcpStream::connect(&t.addr).unwrap();
        let tc = TcpConn::new("", &[with_conn(s), with_hex_dump(buf.clone())]).unwrap();
        let sess = Session::new(tc, None);
        sess.register(&ctx()).unwrap();

        let dump = buf.text();
        assert!(dump.contains(">>> WRITE"), "hex dump missing WRITE direction");
        assert!(dump.contains("<<< READ"), "hex dump missing READ direction");
        assert!(dump.contains("00000000"), "hex dump missing offset column");
        assert!(dump.contains('|'), "hex dump missing ASCII column");

        let _ = sess.unregister(&ctx());
        let _ = sess.close();
    }

    // Go TestHexDumpEIPCIPRequest
    #[test]
    fn hexdump_eip_cip_request() {
        let router = Arc::new(MessageRouter::new());
        router.register_object(0x66, MockObject::new(|_, _, _| Ok(vec![0xDE, 0xAD, 0xBE, 0xEF])));
        let t = FakeTarget::start(router);
        let buf = SharedBuf::default();
        let s = TcpStream::connect(&t.addr).unwrap();
        let tc = TcpConn::new("", &[with_conn(s), with_hex_dump(buf.clone())]).unwrap();
        let sess = Session::new(tc, None);
        sess.register(&ctx()).unwrap();

        let mut p = cip::Path::new();
        p.add_class(0x66);
        p.add_instance(1);
        let req = MessageRouterRequest {
            service: 0x01, // Get Attributes All
            request_path: p,
            request_data: vec![],
        };
        let resp = sess.send_cip_request(&ctx(), &req).unwrap();
        assert!(resp.is_success(), "CIP request failed: {:?}", resp.error());

        let _ = sess.unregister(&ctx());
        let _ = sess.close();

        let dump = buf.text();
        // Should have multiple WRITE/READ pairs (RegisterSession + SendRRData).
        assert!(dump.matches(">>> WRITE").count() >= 2, "expected at least 2 WRITE blocks (register + rr)");
        assert!(dump.matches("<<< READ").count() >= 2, "expected at least 2 READ blocks (register + rr)");
    }

    // Go TestHexDumpEIPAlignedColumns
    #[test]
    fn hexdump_eip_aligned_columns() {
        let t = FakeTarget::start(Arc::new(MessageRouter::new()));
        let buf = SharedBuf::default();
        let s = TcpStream::connect(&t.addr).unwrap();
        let tc = TcpConn::new("", &[with_conn(s), with_hex_dump(buf.clone())]).unwrap();
        let sess = Session::new(tc, None);
        sess.register(&ctx()).unwrap();
        let _ = sess.unregister(&ctx());
        let _ = sess.close();

        let dump = buf.text();
        // Collect hex data lines (starting with an offset).
        let hex_lines: Vec<&str> = dump.trim_end_matches('\n').split('\n').filter(|l| l.len() >= 8 && l.starts_with('0')).collect();
        assert!(!hex_lines.is_empty(), "no hex data lines found in dump");
        // All hex lines should have the same length.
        let expected = hex_lines[0].len();
        for (i, l) in hex_lines.iter().enumerate() {
            assert_eq!(l.len(), expected, "hex line {i} has length {}, expected {expected}: {l:?}", l.len());
        }
    }
}
