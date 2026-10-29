//! Multiple Service Packet (service 0x0A): several Message Router requests in one message.
//!
//! One packet replaces N round trips, which is the dominant cost when polling hundreds of tags.

use super::message::{decode_message_router_response, MessageRouterRequest, MessageRouterResponse};
use super::path::Path;
use super::types::*;

// Ref: ODVA CIP Vol. 1, Common Services - Multiple_Service_Packet (0x0A), sent to the Message
// Router (class 0x02, instance 1) (section unverified).
// Request data: UINT count, UINT offsets[count] (each relative to the start of the count field),
// then the embedded requests back to back.
/// Packs `reqs` into one Multiple_Service_Packet request.
pub fn new_multiple_service_request(reqs: &[MessageRouterRequest]) -> Result<MessageRouterRequest> {
    if reqs.is_empty() {
        return Err(CipError::Other("cip: multiple service packet needs at least one request".into()));
    }
    if reqs.len() > u16::MAX as usize {
        return Err(CipError::Other("cip: too many requests for one multiple service packet".into()));
    }

    let encoded = reqs.iter().map(|r| r.encode()).collect::<Result<Vec<_>>>()?;
    let header = 2 + 2 * reqs.len();
    let total = header + encoded.iter().map(Vec::len).sum::<usize>();
    if total > u16::MAX as usize {
        return Err(CipError::Other("cip: multiple service packet exceeds 65535 bytes".into()));
    }

    let mut data = Vec::with_capacity(total);
    data.extend_from_slice(&(reqs.len() as u16).to_le_bytes());
    let mut offset = header;
    for e in &encoded {
        data.extend_from_slice(&(offset as u16).to_le_bytes());
        offset += e.len();
    }
    for e in &encoded {
        data.extend_from_slice(e);
    }

    let mut path = Path::new();
    path.add_class(CLASS_MESSAGE_ROUTER);
    path.add_instance(1);
    Ok(MessageRouterRequest { service: SERVICE_MULTIPLE_SERVICE_PACKET, request_path: path, request_data: data })
}

// Response data: UINT count, UINT offsets[count], then the embedded replies, each a full Message
// Router response. The packet's own status is 0x00 or 0x1E (an embedded service failed); in both
// cases the embedded replies are present.
/// Splits the `response_data` of a Multiple_Service_Packet reply into its embedded responses.
pub fn decode_multiple_service_response(data: &[u8]) -> Result<Vec<MessageRouterResponse>> {
    let u16_at = |pos: usize| -> Result<usize> {
        let b = data.get(pos..pos + 2).ok_or(CipError::UnexpectedEof)?;
        Ok(u16::from_le_bytes([b[0], b[1]]) as usize)
    };

    if data.is_empty() {
        return Err(CipError::Eof);
    }
    let count = u16_at(0)?;
    let mut offsets = Vec::with_capacity(count + 1);
    for i in 0..count {
        offsets.push(u16_at(2 + 2 * i)?);
    }
    offsets.push(data.len());

    let mut out = Vec::with_capacity(count);
    for w in offsets.windows(2) {
        let (start, end) = (w[0], w[1]);
        if start > end || end > data.len() || start < 2 + 2 * count {
            return Err(CipError::Other(format!("cip: bad multiple service offset {start}..{end}")));
        }
        out.push(decode_message_router_response(&data[start..end])?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cip::{new_read_tag_request, parse_tag_path};

    fn read(tag: &str) -> MessageRouterRequest {
        new_read_tag_request(parse_tag_path(tag).unwrap(), 1)
    }

    #[test]
    fn request_targets_the_message_router_with_offsets_from_the_count_field() {
        let (a, b) = (read("A"), read("BB"));
        let (ea, eb) = (a.encode().unwrap(), b.encode().unwrap());
        let req = new_multiple_service_request(&[a, b]).unwrap();

        assert_eq!(req.service, 0x0A);
        assert_eq!(req.request_path.bytes(), &[0x20, 0x02, 0x24, 0x01]);

        let first = 2 + 2 * 2; // count + two offsets
        let mut want = vec![2, 0];
        want.extend_from_slice(&(first as u16).to_le_bytes());
        want.extend_from_slice(&((first + ea.len()) as u16).to_le_bytes());
        want.extend_from_slice(&ea);
        want.extend_from_slice(&eb);
        assert_eq!(req.request_data, want);
    }

    #[test]
    fn request_golden_bytes_for_one_read() {
        let req = new_multiple_service_request(&[read("A")]).unwrap();
        // count=1, offset=4, then Read Tag "A": 4C 02(words) 91 01 'A' 00 01 00
        assert_eq!(
            req.request_data,
            vec![1, 0, 4, 0, 0x4C, 0x02, 0x91, 0x01, b'A', 0x00, 0x01, 0x00]
        );
    }

    #[test]
    fn empty_request_is_rejected() {
        assert!(new_multiple_service_request(&[]).is_err());
    }

    #[test]
    fn decodes_replies_including_an_embedded_error() {
        let ok = [0xCC, 0, 0, 0, 0xC1, 0x00, 0x01]; // BOOL true
        let bad = [0xCC, 0, 0x04, 0]; // path segment error, no data
        let mut data = vec![2, 0, 6, 0];
        data.extend_from_slice(&(6 + ok.len() as u16).to_le_bytes());
        data.extend_from_slice(&ok);
        data.extend_from_slice(&bad);

        let r = decode_multiple_service_response(&data).unwrap();
        assert_eq!(r.len(), 2);
        assert!(r[0].is_success());
        assert_eq!(r[0].response_data, vec![0xC1, 0x00, 0x01]);
        assert_eq!(r[1].general_status, 0x04);
        assert!(r[1].response_data.is_empty());
    }

    #[test]
    fn truncated_or_out_of_range_offsets_are_errors() {
        assert!(decode_multiple_service_response(&[]).is_err());
        assert!(decode_multiple_service_response(&[1, 0]).is_err(), "missing offset");
        assert!(decode_multiple_service_response(&[1, 0, 99, 0, 0xCC, 0, 0, 0]).is_err(), "offset past end");
    }

    fn reply(status: u8) -> Vec<u8> {
        vec![0xCC, 0, status, 0]
    }

    #[test]
    fn oversize_packets_are_rejected() {
        let big = MessageRouterRequest { request_data: vec![0; 1000], ..read("A") };
        assert!(new_multiple_service_request(&vec![big; 70]).is_err(), "total over 65535 bytes");
        let many = vec![read("A"); u16::MAX as usize + 1];
        assert!(new_multiple_service_request(&many).is_err(), "more than 65535 requests");
    }

    #[test]
    fn zero_count_decodes_to_no_replies() {
        assert!(decode_multiple_service_response(&[0, 0]).unwrap().is_empty());
    }

    #[test]
    fn bad_offsets_are_errors() {
        let ok = reply(0);
        let with = |offsets: &[u16], tail: &[u8]| {
            let mut d = (offsets.len() as u16).to_le_bytes().to_vec();
            for o in offsets {
                d.extend_from_slice(&o.to_le_bytes());
            }
            d.extend_from_slice(tail);
            d
        };
        // 2 replies: header is 6 bytes, so valid offsets are 6 and 10.
        let tail = [ok.clone(), ok.clone()].concat();
        assert_eq!(decode_multiple_service_response(&with(&[6, 10], &tail)).unwrap().len(), 2);
        assert!(decode_multiple_service_response(&with(&[10, 6], &tail)).is_err(), "decreasing offsets");
        assert!(decode_multiple_service_response(&with(&[2, 10], &tail)).is_err(), "first offset inside the table");
        assert!(decode_multiple_service_response(&with(&[6, 14], &tail)).is_err(), "offset at the end: empty reply");
        assert!(decode_multiple_service_response(&with(&[6, 10], &[ok.clone(), vec![0xCC, 0]].concat())).is_err(), "truncated reply");
    }

    #[test]
    fn replies_decode_when_wrapped_in_an_embedded_error_status() {
        // Logix answers 0x1E and still carries every embedded reply.
        let mut body = vec![2, 0, 6, 0, 10, 0];
        body.extend_from_slice(&reply(0));
        body.extend_from_slice(&reply(0x04));
        let outer = MessageRouterResponse {
            service: 0x8A,
            general_status: STATUS_EMBEDDED_SERVICE_ERROR,
            response_data: body,
            ..Default::default()
        };
        let parsed = decode_message_router_response(&outer.encode().unwrap()).unwrap();
        assert!(!parsed.is_success());
        let r = decode_multiple_service_response(&parsed.response_data).unwrap();
        assert_eq!((r[0].general_status, r[1].general_status), (0, 0x04));
    }

    #[test]
    fn encoded_request_round_trips_through_the_decoder() {
        let reads: Vec<_> = ["A", "Bb", "Program:Main.Ccc", "D.e[3]"].into_iter().map(read).collect();
        let req = new_multiple_service_request(&reads).unwrap();
        // Treat each embedded request as a reply-shaped blob: offsets must slice it exactly.
        let data = &req.request_data;
        let count = u16::from_le_bytes([data[0], data[1]]) as usize;
        assert_eq!(count, reads.len());
        for (i, r) in reads.iter().enumerate() {
            let start = u16::from_le_bytes([data[2 + 2 * i], data[3 + 2 * i]]) as usize;
            let want = r.encode().unwrap();
            assert_eq!(&data[start..start + want.len()], &want[..], "request {i}");
        }
    }
}
