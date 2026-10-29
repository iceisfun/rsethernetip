//! Port of Go `runtime/runtime_test.go`.
use super::*;
use std::net::UdpSocket;

fn conn(id: u32) -> IOConnection {
    IOConnection { connection_id: id, stop_chan: Some(StopSignal::new()), ..Default::default() }
}

#[test]
fn add_remove_connection() {
    let rt = Runtime::new(Arc::new(AssemblyObject::new()));
    rt.add_connection(conn(1));
    rt.add_connection(conn(2));
    rt.add_connection(conn(3));
    assert_eq!(rt.connection_count(), 3);
    rt.remove_connection(2);
    assert_eq!(rt.connection_count(), 2);
    assert!(!rt.inner.connections.read().unwrap().contains_key(&2));
    rt.remove_connection(1);
    rt.remove_connection(3);
    assert_eq!(rt.connection_count(), 0);
}

#[test]
fn remove_connection_closes_stop_chan() {
    let rt = Runtime::new(Arc::new(AssemblyObject::new()));
    let stop = StopSignal::new();
    rt.add_connection(IOConnection { connection_id: 42, stop_chan: Some(stop.clone()), ..Default::default() });
    rt.remove_connection(42);
    assert!(stop.wait_timeout(Duration::from_secs(1)), "StopChan was not closed after RemoveConnection");
}

#[test]
fn remove_nonexistent_connection() {
    let rt = Runtime::new(Arc::new(AssemblyObject::new()));
    rt.remove_connection(999);
}

#[test]
fn timeout_closes_stop_chan() {
    let rt = Runtime::new(Arc::new(AssemblyObject::new()));
    rt.start("127.0.0.1:0").unwrap();
    let stop = StopSignal::new();
    rt.add_connection(IOConnection {
        connection_id: 77,
        rpi: Duration::from_millis(10),
        is_consumer: true,
        timeout_mult: 0,
        stop_chan: Some(stop.clone()),
        ..Default::default()
    });
    // Backdate last_receive so the watchdog fires quickly.
    rt.inner.connections.write().unwrap().get_mut(&77).unwrap().last_receive =
        Some(Instant::now() - Duration::from_millis(200));
    assert!(stop.wait_timeout(Duration::from_secs(2)), "StopChan was not closed by watchdog timeout");
    assert!(!rt.inner.connections.read().unwrap().contains_key(&77), "timed-out connection should be removed");
    rt.stop();
}

// Builds a CPF packet: 2 items, address item with connection ID, data item with seq count + payload.
fn build_class1_cpf_packet(conn_id: u32, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&2u16.to_le_bytes());
    b.extend_from_slice(&0x00A1u16.to_le_bytes());
    b.extend_from_slice(&4u16.to_le_bytes());
    b.extend_from_slice(&conn_id.to_le_bytes());
    b.extend_from_slice(&0x00B1u16.to_le_bytes());
    b.extend_from_slice(&((2 + payload.len()) as u16).to_le_bytes());
    b.extend_from_slice(&seq.to_le_bytes());
    b.extend_from_slice(payload);
    b
}

fn wait_for_data(ao: &AssemblyObject, id: u32, want: &[u8]) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if let Ok(d) = ao.get_attribute_single(id, 3)
            && d == want {
                return;
            }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("assembly data = {:02X?}, want {:02X?}", ao.get_attribute_single(id, 3), want);
}

fn send_to(addr: SocketAddr, pkt: &[u8]) {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.send_to(pkt, addr).unwrap();
}

#[test]
fn handle_packet() {
    let ao = Arc::new(AssemblyObject::new());
    ao.register_assembly(100, vec![0; 4]);
    let rt = Runtime::new(ao.clone());
    rt.start("127.0.0.1:0").unwrap();
    rt.add_connection(IOConnection {
        connection_id: 0xAA,
        rpi: Duration::from_secs(1),
        is_consumer: true,
        timeout_mult: 3,
        assembly: ao.get_instance(100),
        stop_chan: Some(StopSignal::new()),
        ..Default::default()
    });
    let payload = [0xDE, 0xAD, 0xBE, 0xEF];
    send_to(rt.addr().unwrap(), &build_class1_cpf_packet(0xAA, 1, &payload));
    wait_for_data(&ao, 100, &payload);
    rt.stop();
}

#[test]
fn handle_packet_with_run_idle_header() {
    let ao = Arc::new(AssemblyObject::new());
    ao.register_assembly(200, vec![0; 4]);
    let rt = Runtime::new(ao.clone());
    rt.start("127.0.0.1:0").unwrap();
    rt.add_connection(IOConnection {
        connection_id: 0xBB,
        rpi: Duration::from_secs(1),
        is_consumer: true,
        timeout_mult: 3,
        assembly: ao.get_instance(200),
        run_idle_header: true,
        stop_chan: Some(StopSignal::new()),
        ..Default::default()
    });
    let asm = [0xCA, 0xFE, 0xBA, 0xBE];
    let mut p = 1u32.to_le_bytes().to_vec();
    p.extend_from_slice(&asm);
    send_to(rt.addr().unwrap(), &build_class1_cpf_packet(0xBB, 1, &p));
    wait_for_data(&ao, 200, &asm);
    rt.stop();
}

#[test]
fn malformed_packets_are_ignored() {
    let ao = Arc::new(AssemblyObject::new());
    let rt = Runtime::new(ao);
    let from: SocketAddr = "127.0.0.1:1".parse().unwrap();
    rt.handle_packet(&[], from);
    rt.handle_packet(&[0xFF; 20], from);
    let mut p = build_class1_cpf_packet(1, 1, &[1, 2]);
    p[12] = 0xFF; // declared data length beyond packet
    rt.handle_packet(&p, from);
}

#[test]
fn scheduler_produces_tick() {
    let ao = Arc::new(AssemblyObject::new());
    ao.register_assembly(101, vec![1, 2, 3, 4]);
    let rt = Runtime::new(ao.clone());
    rt.start("127.0.0.1:0").unwrap();
    let recv = UdpSocket::bind("127.0.0.1:0").unwrap();
    recv.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    rt.add_connection(IOConnection {
        connection_id: 0xCC,
        rpi: Duration::from_millis(10),
        is_producer: true,
        assembly: ao.get_instance(101),
        remote_addr: Some(recv.local_addr().unwrap()),
        stop_chan: Some(StopSignal::new()),
        ..Default::default()
    });
    let sched = Scheduler::new(&rt);
    sched.start();
    let mut buf = [0u8; 2048];
    let (n, _) = recv.recv_from(&mut buf).expect("recv");
    assert!(n >= 18, "packet too short: {n} bytes");
    let d = &buf[..n];
    assert_eq!(u16::from_le_bytes([d[0], d[1]]), 2);
    assert_eq!(u32::from_le_bytes([d[6], d[7], d[8], d[9]]), 0xCC);
    assert!(u16::from_le_bytes([d[16], d[17]]) >= 6);
    assert_ne!(u16::from_le_bytes([d[18], d[19]]), 0, "sequence count should not be 0");
    assert_eq!(&d[20..24], &[1, 2, 3, 4]);
    sched.stop();
    sched.stop();
    rt.stop();
}
