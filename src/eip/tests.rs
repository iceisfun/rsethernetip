// Ported from goindustrial protocol/ethernetip/eip/eip_test.go.
use super::*;

const CTX: [u8; 8] = [0xD7, 0xA5, 0x7E, 0x26, 0x73, 0xC0, 0x35, 0xF4];

fn dec(raw: &[u8]) -> EncapsulationHeader {
    EncapsulationHeader::decode(&mut &raw[..]).unwrap()
}

#[test]
fn header_encode_decode_round_trip() {
    let original = EncapsulationHeader {
        command: COMMAND_REGISTER_SESSION,
        length: 4,
        session_handle: 0x00060212,
        status: 0,
        sender_context: CTX,
        options: 0,
    };
    let mut buf = Vec::new();
    original.encode(&mut buf).unwrap();
    assert_eq!(buf.len(), HEADER_SIZE);
    let d = dec(&buf);
    assert_eq!(d.command, original.command);
    assert_eq!(d.length, original.length);
    assert_eq!(d.session_handle, original.session_handle);
    assert_eq!(d.sender_context, original.sender_context);
}

#[test]
fn decode_raw_list_identity() {
    let raw = [0x63, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let h = dec(&raw);
    assert_eq!(h.command, COMMAND_LIST_IDENTITY);
    assert_eq!(h.length, 0);
    assert_eq!(h.session_handle, 0);
    assert_eq!(h.status, 0);
}

#[test]
fn decode_raw_register_session() {
    let raw = [
        0x65, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD7, 0xA5, 0x7E,
        0x26, 0x73, 0xC0, 0x35, 0xF4, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ];
    let h = dec(&raw[..HEADER_SIZE]);
    assert_eq!(h.command, COMMAND_REGISTER_SESSION);
    assert_eq!(h.length, 4);
    assert_eq!(h.session_handle, 0);
    let data = &raw[HEADER_SIZE..];
    assert_eq!(u16::from_le_bytes([data[0], data[1]]), 1);
    assert_eq!(u16::from_le_bytes([data[2], data[3]]), 0);
    assert_eq!(h.sender_context, CTX);
}

#[test]
fn decode_raw_send_rr_data() {
    let raw = [
        0x6F, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0xDD, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let h = dec(&raw);
    assert_eq!(h.command, COMMAND_SEND_RR_DATA);
    assert_eq!(h.length, 12);
    assert_eq!(h.session_handle, 1);
}

#[test]
fn decode_raw_list_identity_from_test() {
    let raw = [
        0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD7, 0xDD, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let h = dec(&raw);
    assert_eq!(h.command, COMMAND_LIST_IDENTITY);
    assert_eq!(h.sender_context, [0xD7, 0xDD, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn decode_raw_list_services() {
    let raw = [
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0xDD, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let h = dec(&raw);
    assert_eq!(h.command, COMMAND_LIST_SERVICES);
    assert_eq!(h.length, 0);
}

#[test]
fn decode_raw_invalid_protocol_version() {
    let raw = [
        0x65, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x67, 0x88, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let h = dec(&raw[..HEADER_SIZE]);
    assert_eq!(h.command, COMMAND_REGISTER_SESSION);
    let data = &raw[HEADER_SIZE..];
    assert_eq!(u16::from_le_bytes([data[0], data[1]]), 0);
}

#[test]
fn decode_raw_forward_open() {
    let raw = [
        0x6F, 0x00, 0x40, 0x00, 0x00, 0x06, 0x02, 0x12, 0x00, 0x00, 0x00, 0x00, 0xBC, 0x6F, 0xFA,
        0x27, 0x04, 0x18, 0x83, 0xBA, 0x00, 0x00, 0x00, 0x00,
    ];
    let h = dec(&raw);
    assert_eq!(h.command, COMMAND_SEND_RR_DATA);
    assert_eq!(h.length, 64);
    assert_ne!(h.session_handle, 0);
}

#[test]
fn header_bytes() {
    let h = EncapsulationHeader { command: COMMAND_LIST_IDENTITY, length: 0, ..Default::default() };
    let d = h.bytes();
    assert_eq!(d.len(), HEADER_SIZE);
    assert_eq!(u16::from_le_bytes([d[0], d[1]]), COMMAND_LIST_IDENTITY.0);
}

#[test]
fn header_string() {
    let h = EncapsulationHeader {
        command: COMMAND_REGISTER_SESSION,
        length: 4,
        session_handle: 1,
        ..Default::default()
    };
    let s = h.to_string();
    assert!(!s.is_empty());
    assert_eq!(s, "Cmd: RegisterSession (0x0065), Len: 4, Session: 0x00000001, Status: 0x00000000");
}

#[test]
fn command_string() {
    let tests = [
        (COMMAND_NOP, "Nop"),
        (COMMAND_LIST_SERVICES, "ListServices"),
        (COMMAND_LIST_IDENTITY, "ListIdentity"),
        (COMMAND_LIST_INTERFACES, "ListInterfaces"),
        (COMMAND_REGISTER_SESSION, "RegisterSession"),
        (COMMAND_UNREGISTER_SESSION, "UnregisterSession"),
        (COMMAND_SEND_RR_DATA, "SendRRData"),
        (COMMAND_SEND_UNIT_DATA, "SendUnitData"),
        (COMMAND_INDICATE_STATUS, "IndicateStatus"),
        (COMMAND_CANCEL, "Cancel"),
    ];
    for (c, w) in tests {
        assert_eq!(c.to_string(), w);
    }
    assert_eq!(Command(0xFFFF).to_string(), "UnknownCommand(0xFFFF)");
}

#[test]
fn register_session_data_encode() {
    let data = RegisterSessionData::new().encode().unwrap();
    assert_eq!(data.len(), 4);
    assert_eq!(u16::from_le_bytes([data[0], data[1]]), 1);
    assert_eq!(u16::from_le_bytes([data[2], data[3]]), 0);
}

#[test]
fn eip_status_codes() {
    assert_eq!(STATUS_SUCCESS, 0);
    assert_eq!(STATUS_INVALID_COMMAND, 1);
    assert_eq!(STATUS_INSUFFICIENT_MEMORY, 2);
    assert_eq!(STATUS_INCORRECT_DATA, 3);
    assert_eq!(STATUS_INVALID_SESSION_HANDLE, 0x64);
    assert_eq!(STATUS_INVALID_LENGTH, 0x65);
    assert_eq!(STATUS_UNSUPPORTED_PROTOCOL, 0x69);
}

fn roundtrip(items: Vec<CpfItem>) -> CommonPacketFormat {
    let data = CommonPacketFormat::new(items).encode().unwrap();
    CommonPacketFormat::decode(&data).unwrap()
}

#[test]
fn cpf_null_address_round_trip() {
    let d = roundtrip(vec![
        CpfItem::new(ITEM_ID_NULL_ADDRESS, vec![]),
        CpfItem::new(ITEM_ID_UNCONNECTED_MESSAGE, vec![0x4C, 0x02, 0x20, 0x04, 0x24, 0x01]),
    ]);
    assert_eq!(d.item_count, 2);
    assert_eq!(d.find_item_by_type(ITEM_ID_NULL_ADDRESS).unwrap().length, 0);
    assert_eq!(d.find_item_by_type(ITEM_ID_UNCONNECTED_MESSAGE).unwrap().length, 6);
}

#[test]
fn cpf_connected_address_round_trip() {
    let conn_id = 0x12345678u32.to_le_bytes().to_vec();
    let mut conn_data = 1u16.to_le_bytes().to_vec();
    conn_data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
    let d = roundtrip(vec![
        CpfItem::new(ITEM_ID_CONNECTION_BASED, conn_id),
        CpfItem::new(ITEM_ID_CONNECTED_TRANSPORT, conn_data),
    ]);
    assert_eq!(d.item_count, 2);
    let a = d.find_item_by_type(ITEM_ID_CONNECTION_BASED).unwrap();
    assert_eq!(u32::from_le_bytes(a.data[0..4].try_into().unwrap()), 0x12345678);
    let t = d.find_item_by_type(ITEM_ID_CONNECTED_TRANSPORT).unwrap();
    assert_eq!(u16::from_le_bytes([t.data[0], t.data[1]]), 1);
}

#[test]
fn cpf_sequenced_address_item() {
    let mut a = Vec::new();
    a.extend_from_slice(&0xAABBCCDDu32.to_le_bytes());
    a.extend_from_slice(&42u32.to_le_bytes());
    let d = roundtrip(vec![
        CpfItem::new(ITEM_ID_SEQUENCED_ADDRESS, a),
        CpfItem::new(ITEM_ID_CONNECTED_TRANSPORT, vec![1, 2, 3]),
    ]);
    let s = d.find_item_by_type(ITEM_ID_SEQUENCED_ADDRESS).unwrap();
    assert_eq!(s.length, 8);
    assert_eq!(u32::from_le_bytes(s.data[0..4].try_into().unwrap()), 0xAABBCCDD);
    assert_eq!(u32::from_le_bytes(s.data[4..8].try_into().unwrap()), 42);
}

#[test]
fn cpf_sockaddr_info_item() {
    let mut s = vec![0u8; 16];
    s[0..2].copy_from_slice(&2u16.to_be_bytes());
    s[2..4].copy_from_slice(&0x08AEu16.to_be_bytes());
    s[4..8].copy_from_slice(&[192, 168, 1, 10]);
    let d = roundtrip(vec![
        CpfItem::new(ITEM_ID_NULL_ADDRESS, vec![]),
        CpfItem::new(ITEM_ID_UNCONNECTED_MESSAGE, vec![0x01]),
        CpfItem::new(ITEM_ID_SOCKADDR_INFO, s),
    ]);
    assert_eq!(d.item_count, 3);
    let it = d.find_item_by_type(ITEM_ID_SOCKADDR_INFO).unwrap();
    assert_eq!(it.length, 16);
    assert_eq!(u16::from_be_bytes([it.data[0], it.data[1]]), 2);
    assert_eq!(u16::from_be_bytes([it.data[2], it.data[3]]), 0x08AE);
}

#[test]
fn cpf_list_identity_response_item() {
    let v = vec![0x01, 0x00, 0x0C, 0x00, 0x2B, 0x00];
    let d = roundtrip(vec![CpfItem::new(ITEM_ID_LIST_IDENTITY, v.clone())]);
    assert_eq!(d.find_item_by_type(ITEM_ID_LIST_IDENTITY).unwrap().data, v);
}

#[test]
fn cpf_list_services_response_item() {
    let v = vec![0x01, 0x00, 0x20, 0x01, 0x00, 0x00];
    let d = roundtrip(vec![CpfItem::new(ITEM_ID_LIST_SERVICES, v.clone())]);
    assert_eq!(d.find_item_by_type(ITEM_ID_LIST_SERVICES).unwrap().data, v);
}

#[test]
fn cpf_empty_items() {
    let data = CommonPacketFormat::new(vec![]).encode().unwrap();
    assert_eq!(data.len(), 2);
    assert_eq!(CommonPacketFormat::decode(&data).unwrap().item_count, 0);
}

#[test]
fn cpf_find_item_by_type_not_found() {
    let c = CommonPacketFormat::new(vec![CpfItem::new(ITEM_ID_NULL_ADDRESS, vec![])]);
    assert!(c.find_item_by_type(ITEM_ID_UNCONNECTED_MESSAGE).is_none());
}

#[test]
fn cpf_decode_truncated_header() {
    assert!(CommonPacketFormat::decode(&[0x01]).is_err());
}

#[test]
fn cpf_decode_item_count_exceeds_data() {
    let e = CommonPacketFormat::decode(&5u16.to_le_bytes()).unwrap_err();
    assert_eq!(
        e.to_string(),
        "cpf: item count 5 requires at least 20 bytes but only 0 remain"
    );
}

#[test]
fn cpf_decode_truncated_item() {
    // 1 item declared, type ID only, missing length
    let mut b = 1u16.to_le_bytes().to_vec();
    b.extend_from_slice(&0u16.to_le_bytes());
    assert!(CommonPacketFormat::decode(&b).is_err());
}

#[test]
fn cpf_decode_item_data_truncated() {
    let b = [1, 0, 0xB2, 0, 0xFF, 0xFF];
    assert!(CommonPacketFormat::decode(&b).is_err());
}

#[test]
fn header_decode_short() {
    assert!(EncapsulationHeader::decode(&mut &[0u8; 10][..]).is_err());
}

#[test]
fn header_sender_context_preserved() {
    let ctx = [1, 2, 3, 4, 5, 6, 7, 8];
    let h = EncapsulationHeader { command: COMMAND_LIST_IDENTITY, sender_context: ctx, ..Default::default() };
    assert_eq!(dec(&h.bytes()).sender_context, ctx);
}

#[test]
fn header_max_values() {
    let h = EncapsulationHeader {
        command: Command(0xFFFF),
        length: 0xFFFF,
        session_handle: 0xFFFF_FFFF,
        status: 0xFFFF_FFFF,
        sender_context: [0xFF; 8],
        options: 0xFFFF_FFFF,
    };
    let data = h.bytes();
    assert_eq!(data.len(), HEADER_SIZE);
    let d = dec(&data);
    assert_eq!(d.command, h.command);
    assert_eq!(d.session_handle, h.session_handle);
    assert_eq!(d, h);
}

// cpppo captures

#[test]
fn decode_register_session_request() {
    let mut raw = vec![0x65, 0x00, 0x04, 0x00];
    raw.extend_from_slice(&[0u8; 20]);
    let h = dec(&raw);
    assert_eq!(h.command, COMMAND_REGISTER_SESSION);
    assert_eq!(h.length, 4);
    assert_eq!(h.session_handle, 0);
}

#[test]
fn decode_register_session_reply() {
    let mut raw = vec![0x65, 0x00, 0x04, 0x00, 0x01, 0x1e, 0x02, 0x11];
    raw.extend_from_slice(&[0u8; 16]);
    let h = dec(&raw);
    assert_eq!(h.command, COMMAND_REGISTER_SESSION);
    assert_eq!(h.session_handle, 0x11021e01);
    assert_eq!(h.status, 0);
}

#[test]
fn decode_send_rr_data_request() {
    let raw = [
        0x6f, 0x00, 0x16, 0x00, 0x01, 0x1e, 0x02, 0x11, 0, 0, 0, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0,
    ];
    let h = dec(&raw);
    assert_eq!(h.command, COMMAND_SEND_RR_DATA);
    assert_eq!(h.length, 22);
    assert_eq!(h.session_handle, 0x11021e01);
}

#[test]
fn decode_get_attribute_all_reply() {
    let raw = [
        0x6f, 0x00, 0x37, 0x00, 0x01, 0x1e, 0x02, 0x11, 0, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0,
    ];
    let h = dec(&raw);
    assert_eq!(h.command, COMMAND_SEND_RR_DATA);
    assert_eq!(h.length, 0x37);
    assert_eq!(h.sender_context[0], 0x02);
}

#[test]
fn decode_read_tag_fragmented_error() {
    let raw = [
        0x6f, 0x00, 0x14, 0x00, 0x02, 0x67, 0x02, 0x10, 0, 0, 0, 0, 0x07, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0,
    ];
    let h = dec(&raw);
    assert_eq!(h.command, COMMAND_SEND_RR_DATA);
    assert_eq!(h.status, 0);
    assert_eq!(h.session_handle, 0x10026702);
}

#[test]
fn decode_cpf_unconnected_send() {
    let d = [
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x00, 0x06, 0x00, 0x01, 0x02, 0x20, 0x66, 0x24,
        0x01,
    ];
    let c = CommonPacketFormat::decode(&d).unwrap();
    assert_eq!(c.items.len(), 2);
    assert_eq!(c.items[0].type_id, ITEM_ID_NULL_ADDRESS);
    assert_eq!(c.items[0].length, 0);
    assert_eq!(c.items[1].type_id, ITEM_ID_UNCONNECTED_MESSAGE);
    assert_eq!(c.items[1].length, 6);
    assert_eq!(c.items[1].data.len(), 6);
    assert_eq!(c.items[1].data[0], 0x01);
}

#[test]
fn decode_cpf_send_rr_data_reply() {
    let d = [
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x00, 0x16, 0x00, 0x81, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00, 0x00, 0x2d, 0x00, 0x01, 0x00, 0x01, 0x01, 0xb1, 0x2a, 0x1b, 0x00,
        0x0a, 0x00,
    ];
    let c = CommonPacketFormat::decode(&d).unwrap();
    assert_eq!(c.items.len(), 2);
    assert_eq!(c.items[1].length, 22);
    assert_eq!(c.items[1].data[0], 0x81);
}

#[test]
fn register_session_data_payload() {
    let r = RegisterSessionData { protocol_version: 1, options_flags: 0 };
    assert_eq!(r.encode().unwrap(), vec![0x01, 0x00, 0x00, 0x00]);
}

#[test]
fn eip_command_codes() {
    assert_eq!(COMMAND_REGISTER_SESSION.0, 0x0065);
    assert_eq!(COMMAND_SEND_RR_DATA.0, 0x006F);
    assert_eq!(COMMAND_LIST_IDENTITY.0, 0x0063);
    assert_eq!(COMMAND_LIST_SERVICES.0, 0x0004);
    assert_eq!(COMMAND_NOP.0, 0x0000);
}

#[test]
fn cpf_item_ids() {
    assert_eq!(ITEM_ID_NULL_ADDRESS, 0x0000);
    assert_eq!(ITEM_ID_UNCONNECTED_MESSAGE, 0x00B2);
    assert_eq!(ITEM_ID_CONNECTED_TRANSPORT, 0x00B1);
    assert_eq!(ITEM_ID_CONNECTION_BASED, 0x00A1);
}

// Discovery (no Go tests; added coverage for the ported encode/decode)

#[test]
fn list_identity_round_trip_and_skip_unknown() {
    let it = ListIdentityItem {
        type_id: ITEM_ID_LIST_IDENTITY,
        encaps_version: 1,
        vendor_id: 1,
        device_type: 14,
        product_code: 55,
        revision: [20, 11],
        status: 0x30,
        serial_number: 0xDEADBEEF,
        product_name: "1756-L61".into(),
        state: 3,
        ..Default::default()
    };
    let mut data = encode_list_identity_response(std::slice::from_ref(&it)).unwrap();
    let got = decode_list_identity_response(&data).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].length, 34 + 8);
    assert_eq!(got[0].product_name, "1756-L61");
    assert_eq!(got[0].serial_number, 0xDEADBEEF);
    assert_eq!(got[0].revision, [20, 11]);
    // unknown item type skipped
    data[0] = 2;
    data.extend_from_slice(&[0x99, 0x00, 0x02, 0x00, 0xAA, 0xBB]);
    assert_eq!(decode_list_identity_response(&data).unwrap().len(), 1);
    // truncated
    assert!(decode_list_identity_response(&data[..10]).is_err());
}

#[test]
fn list_identity_name_truncated_to_32() {
    let it = ListIdentityItem { type_id: ITEM_ID_LIST_IDENTITY, product_name: "x".repeat(40), ..Default::default() };
    let data = encode_list_identity_response(&[it]).unwrap();
    assert_eq!(decode_list_identity_response(&data).unwrap()[0].product_name.len(), 32);
}

#[test]
fn list_services_round_trip() {
    let it = ListServicesItem {
        type_id: ITEM_ID_LIST_SERVICES,
        version: 1,
        capability_flags: 0x0120,
        name: "Communications".into(),
        ..Default::default()
    };
    let data = encode_list_services_response(&[it]).unwrap();
    assert_eq!(data.len(), 2 + 4 + 20);
    let got = decode_list_services_response(&data).unwrap();
    assert_eq!(got[0].name, "Communications");
    assert_eq!(got[0].length, 20);
    assert_eq!(got[0].capability_flags, 0x0120);
    assert!(decode_list_services_response(&data[..data.len() - 1]).is_err());
}

#[test]
fn huge_declared_count_is_bounded() {
    assert!(decode_list_identity_response(&[0xFF, 0xFF]).is_err());
    assert!(decode_list_services_response(&[0xFF, 0xFF]).is_err());
}
