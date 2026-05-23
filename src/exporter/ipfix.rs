use std::io::Write;
use byteorder::{BigEndian, WriteBytesExt};
use crate::exporter::{SendParameter, get_active_now};

// IPFIX Constants
const IPFIX_TEMPLATE_SET_ID: u16 = 2;

const IPFIX_SOFTFLOWD_V4_TEMPLATE_ID: u16 = 1024;
const IPFIX_SOFTFLOWD_V6_TEMPLATE_ID: u16 = 2048;

// Field IDs
const IPFIX_SOURCE_IPV4_ADDRESS: u16 = 8;
const IPFIX_DESTINATION_IPV4_ADDRESS: u16 = 12;
const IPFIX_SOURCE_IPV6_ADDRESS: u16 = 27;
const IPFIX_DESTINATION_IPV6_ADDRESS: u16 = 28;
const IPFIX_OCTET_DELTA_COUNT: u16 = 1;
const IPFIX_PACKET_DELTA_COUNT: u16 = 2;
const IPFIX_INGRESS_INTERFACE: u16 = 10;
const IPFIX_EGRESS_INTERFACE: u16 = 14;
const IPFIX_FLOW_DIRECTION: u16 = 61;
const IPFIX_FLOW_END_REASON: u16 = 136;
const IPFIX_SOURCE_TRANSPORT_PORT: u16 = 7;
const IPFIX_DESTINATION_TRANSPORT_PORT: u16 = 11;
const IPFIX_PROTOCOL_IDENTIFIER: u16 = 4;
const IPFIX_TCP_CONTROL_BITS: u16 = 6;
const IPFIX_IP_VERSION: u16 = 60;
const IPFIX_IP_CLASS_OF_SERVICE: u16 = 5;
const IPFIX_VLAN_ID: u16 = 58;
const IPFIX_POST_VLAN_ID: u16 = 59;
const IPFIX_SOURCE_MAC_ADDRESS: u16 = 56;
const IPFIX_POST_DESTINATION_MAC_ADDRESS: u16 = 80;
const IPFIX_FLOW_START_MILLISECONDS: u16 = 152;
const IPFIX_FLOW_END_MILLISECONDS: u16 = 153;

static mut PKTS_UNTIL_TEMPLATE: i32 = -1;

fn write_templates(packet: &mut Vec<u8>) {
    // 1. IPv4 Template Flowset
    packet.write_u16::<BigEndian>(IPFIX_TEMPLATE_SET_ID).unwrap();
    // Flowset Length: 4 (set header) + 4 (template record header) + 14 * 4 (fields) = 64
    packet.write_u16::<BigEndian>(64).unwrap();
    packet.write_u16::<BigEndian>(IPFIX_SOFTFLOWD_V4_TEMPLATE_ID).unwrap();
    packet.write_u16::<BigEndian>(14).unwrap(); // 14 fields

    let v4_fields = [
        (IPFIX_SOURCE_IPV4_ADDRESS, 4),
        (IPFIX_DESTINATION_IPV4_ADDRESS, 4),
        (IPFIX_OCTET_DELTA_COUNT, 4),
        (IPFIX_PACKET_DELTA_COUNT, 4),
        (IPFIX_INGRESS_INTERFACE, 4),
        (IPFIX_EGRESS_INTERFACE, 4),
        (IPFIX_SOURCE_TRANSPORT_PORT, 2),
        (IPFIX_DESTINATION_TRANSPORT_PORT, 2),
        (IPFIX_PROTOCOL_IDENTIFIER, 1),
        (IPFIX_TCP_CONTROL_BITS, 1),
        (IPFIX_IP_VERSION, 1),
        (IPFIX_IP_CLASS_OF_SERVICE, 1),
        (IPFIX_FLOW_START_MILLISECONDS, 8),
        (IPFIX_FLOW_END_MILLISECONDS, 8),
    ];
    for &(id, len) in &v4_fields {
        packet.write_u16::<BigEndian>(id).unwrap();
        packet.write_u16::<BigEndian>(len).unwrap();
    }

    // 2. IPv6 Template Flowset
    packet.write_u16::<BigEndian>(IPFIX_TEMPLATE_SET_ID).unwrap();
    // Flowset Length: 4 + 4 + 14 * 4 = 64
    packet.write_u16::<BigEndian>(64).unwrap();
    packet.write_u16::<BigEndian>(IPFIX_SOFTFLOWD_V6_TEMPLATE_ID).unwrap();
    packet.write_u16::<BigEndian>(14).unwrap();

    let v6_fields = [
        (IPFIX_SOURCE_IPV6_ADDRESS, 16),
        (IPFIX_DESTINATION_IPV6_ADDRESS, 16),
        (IPFIX_OCTET_DELTA_COUNT, 4),
        (IPFIX_PACKET_DELTA_COUNT, 4),
        (IPFIX_INGRESS_INTERFACE, 4),
        (IPFIX_EGRESS_INTERFACE, 4),
        (IPFIX_SOURCE_TRANSPORT_PORT, 2),
        (IPFIX_DESTINATION_TRANSPORT_PORT, 2),
        (IPFIX_PROTOCOL_IDENTIFIER, 1),
        (IPFIX_TCP_CONTROL_BITS, 1),
        (IPFIX_IP_VERSION, 1),
        (IPFIX_IP_CLASS_OF_SERVICE, 1),
        (IPFIX_FLOW_START_MILLISECONDS, 8),
        (IPFIX_FLOW_END_MILLISECONDS, 8),
    ];
    for &(id, len) in &v6_fields {
        packet.write_u16::<BigEndian>(id).unwrap();
        packet.write_u16::<BigEndian>(len).unwrap();
    }
}

pub fn send_ipfix(sp: SendParameter) -> i32 {
    let now = get_active_now(sp.param);
    let mut packet = Vec::with_capacity(1500);
    let mut flows_in_packet = 0;
    let mut num_packets = 0;
    let mut current_template_id = 0;
    let mut offset_to_flowset_len = 0;
    let mut flowset_start_offset = 0;

    let target_flows = sp.flows;
    let ifidx = sp.ifidx;

    let mut send_templates_now = false;
    unsafe {
        if PKTS_UNTIL_TEMPLATE <= 0 {
            send_templates_now = true;
            PKTS_UNTIL_TEMPLATE = 16;
        }
        PKTS_UNTIL_TEMPLATE -= 1;
    }

    if send_templates_now {
        packet.clear();
        packet.write_u16::<BigEndian>(10).unwrap(); // Version (IPFIX)
        packet.write_u16::<BigEndian>(0).unwrap(); // Length (fill later)
        packet.write_u32::<BigEndian>(now.tv_sec as u32).unwrap();
        packet.write_u32::<BigEndian>(sp.param.records_sent as u32).unwrap(); // Sequence
        packet.write_u32::<BigEndian>(0).unwrap(); // Observation Domain ID

        write_templates(&mut packet);

        let packet_len = packet.len() as u16;
        packet[2] = (packet_len >> 8) as u8;
        packet[3] = (packet_len & 0xFF) as u8;

        let mut sent = 0;
        let _ = sp.target.send_multi_destinations(&packet, &mut sent);
        sp.param.packets_sent += 1;
        packet.clear();
    }

    for flow in target_flows {
        let is_v6 = flow.key.af == 10;
        let flow_template_id = if is_v6 { IPFIX_SOFTFLOWD_V6_TEMPLATE_ID } else { IPFIX_SOFTFLOWD_V4_TEMPLATE_ID };

        for dir in 0..2 {
            if flow.octets[dir] == 0 {
                continue;
            }

            if packet.len() >= 1400 || (flows_in_packet > 0 && current_template_id != flow_template_id) {
                // Close current flowset
                let flowset_len = (packet.len() - flowset_start_offset) as u16;
                packet[offset_to_flowset_len] = (flowset_len >> 8) as u8;
                packet[offset_to_flowset_len + 1] = (flowset_len & 0xFF) as u8;

                // Send packet
                if let Err(e) = send_packet(&mut packet, &sp) {
                    log::error!("Failed to send IPFIX packet: {}", e);
                    sp.param.flows_dropped += flows_in_packet as u64;
                    return -1;
                }
                sp.param.records_sent += flows_in_packet as u64;
                sp.param.flows_exported += flows_in_packet as u64;
                flows_in_packet = 0;
                num_packets += 1;
                current_template_id = 0;
            }

            if packet.is_empty() {
                packet.write_u16::<BigEndian>(10).unwrap(); // Version
                packet.write_u16::<BigEndian>(0).unwrap(); // Length (fill at end)
                packet.write_u32::<BigEndian>(now.tv_sec as u32).unwrap();
                packet.write_u32::<BigEndian>((sp.param.records_sent + sp.param.flows_exported) as u32).unwrap();
                packet.write_u32::<BigEndian>(0).unwrap();
            }

            if current_template_id != flow_template_id {
                if current_template_id != 0 {
                    // Close previous flowset
                    let flowset_len = (packet.len() - flowset_start_offset) as u16;
                    packet[offset_to_flowset_len] = (flowset_len >> 8) as u8;
                    packet[offset_to_flowset_len + 1] = (flowset_len & 0xFF) as u8;
                }

                // Start new flowset
                flowset_start_offset = packet.len();
                packet.write_u16::<BigEndian>(flow_template_id).unwrap();
                offset_to_flowset_len = packet.len();
                packet.write_u16::<BigEndian>(0).unwrap(); // Flowset length placeholder

                current_template_id = flow_template_id;
            }

            // Write Flow Record data
            if is_v6 {
                let src_bytes = match flow.key.addr[dir] {
                    std::net::IpAddr::V6(ip) => ip.octets(),
                    _ => [0; 16],
                };
                let dst_bytes = match flow.key.addr[dir ^ 1] {
                    std::net::IpAddr::V6(ip) => ip.octets(),
                    _ => [0; 16],
                };
                packet.write_all(&src_bytes).unwrap();
                packet.write_all(&dst_bytes).unwrap();
            } else {
                let src_ip = match flow.key.addr[dir] {
                    std::net::IpAddr::V4(ip) => u32::from(ip),
                    _ => 0,
                };
                let dst_ip = match flow.key.addr[dir ^ 1] {
                    std::net::IpAddr::V4(ip) => u32::from(ip),
                    _ => 0,
                };
                packet.write_u32::<BigEndian>(src_ip).unwrap();
                packet.write_u32::<BigEndian>(dst_ip).unwrap();
            }

            packet.write_u32::<BigEndian>(flow.octets[dir]).unwrap();
            packet.write_u32::<BigEndian>(flow.packets[dir]).unwrap();
            packet.write_u32::<BigEndian>(ifidx as u32).unwrap();
            packet.write_u32::<BigEndian>(ifidx as u32).unwrap();
            packet.write_u16::<BigEndian>(flow.key.port[dir].to_be()).unwrap();
            packet.write_u16::<BigEndian>(flow.key.port[dir ^ 1].to_be()).unwrap();
            packet.write_u8(flow.key.protocol).unwrap();
            packet.write_u8(flow.tcp_flags[dir]).unwrap();
            packet.write_u8(if is_v6 { 6 } else { 4 }).unwrap();
            packet.write_u8(flow.tos[dir]).unwrap();

            // Flow start and end in Milliseconds since Unix epoch (IPFIX standard)
            let start_ms = (flow.flow_start.tv_sec * 1000) as u64 + (flow.flow_start.tv_usec / 1000) as u64;
            let end_ms = (flow.flow_last.tv_sec * 1000) as u64 + (flow.flow_last.tv_usec / 1000) as u64;
            packet.write_u64::<BigEndian>(start_ms).unwrap();
            packet.write_u64::<BigEndian>(end_ms).unwrap();

            flows_in_packet += 1;
        }
    }

    if flows_in_packet > 0 {
        // Close last flowset
        let flowset_len = (packet.len() - flowset_start_offset) as u16;
        packet[offset_to_flowset_len] = (flowset_len >> 8) as u8;
        packet[offset_to_flowset_len + 1] = (flowset_len & 0xFF) as u8;

        if let Err(e) = send_packet(&mut packet, &sp) {
            log::error!("Failed to send IPFIX leftovers: {}", e);
            sp.param.flows_dropped += flows_in_packet as u64;
            return -1;
        }
        sp.param.records_sent += flows_in_packet as u64;
        sp.param.flows_exported += flows_in_packet as u64;
        num_packets += 1;
    }

    sp.param.packets_sent += num_packets;
    num_packets as i32
}

fn send_packet(packet: &mut [u8], sp: &SendParameter) -> std::io::Result<()> {
    // Fill IPFIX total length in header
    let len = packet.len() as u16;
    packet[2] = (len >> 8) as u8;
    packet[3] = (len & 0xFF) as u8;

    let mut sent = 0;
    sp.target.send_multi_destinations(packet, &mut sent)
}
