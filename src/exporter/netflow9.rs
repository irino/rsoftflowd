use std::io::Write;
use byteorder::{BigEndian, WriteBytesExt, ByteOrder};
use crate::exporter::{SendParameter, get_active_now};

// Netflow v9 Constants
const NF9_TEMPLATE_SET_ID: u16 = 0;
const NF9_OPTION_TEMPLATE_SET_ID: u16 = 1;

const NF9_SOFTFLOWD_V4_TEMPLATE_ID: u16 = 1024;
const NF9_SOFTFLOWD_V6_TEMPLATE_ID: u16 = 2048;
const NF9_SOFTFLOWD_OPTION_TEMPLATE_ID: u16 = 256;

const NF9_IPV4_SRC_ADDR: u16 = 8;
const NF9_IPV4_DST_ADDR: u16 = 12;
const NF9_IPV6_SRC_ADDR: u16 = 27;
const NF9_IPV6_DST_ADDR: u16 = 28;
const NF9_LAST_SWITCHED: u16 = 21;
const NF9_FIRST_SWITCHED: u16 = 22;
const NF9_IN_BYTES: u16 = 1;
const NF9_IN_PACKETS: u16 = 2;
const NF9_IF_INDEX_IN: u16 = 10;
const NF9_IF_INDEX_OUT: u16 = 14;
const NF9_L4_SRC_PORT: u16 = 7;
const NF9_L4_DST_PORT: u16 = 11;
const NF9_PROTOCOL: u16 = 4;
const NF9_TCP_FLAGS: u16 = 6;
const NF9_IP_PROTOCOL_VERSION: u16 = 60;
const NF9_TOS: u16 = 5;
const NF9_ICMP_TYPE: u16 = 32;
const NF9_SRC_VLAN: u16 = 58;

// Option Template Constants
const NFLOW9_OPTION_SCOPE_INTERFACE: u16 = 2;
const NFLOW9_SAMPLING_INTERVAL: u16 = 34;
const NFLOW9_SAMPLING_ALGORITHM: u16 = 35;

static mut PKTS_UNTIL_TEMPLATE: i32 = -1;

fn write_templates(packet: &mut Vec<u8>) {
    // 1. Write IPv4 Template (flowset_id=0, length=4+4+16*4 = 72)
    packet.write_u16::<BigEndian>(NF9_TEMPLATE_SET_ID).unwrap();
    packet.write_u16::<BigEndian>(72).unwrap(); // Total template flowset length
    packet.write_u16::<BigEndian>(NF9_SOFTFLOWD_V4_TEMPLATE_ID).unwrap();
    packet.write_u16::<BigEndian>(16).unwrap(); // Fields count

    let v4_fields = [
        (NF9_IPV4_SRC_ADDR, 4),
        (NF9_IPV4_DST_ADDR, 4),
        (NF9_LAST_SWITCHED, 4),
        (NF9_FIRST_SWITCHED, 4),
        (NF9_IN_BYTES, 4),
        (NF9_IN_PACKETS, 4),
        (NF9_IF_INDEX_IN, 4),
        (NF9_IF_INDEX_OUT, 4),
        (NF9_L4_SRC_PORT, 2),
        (NF9_L4_DST_PORT, 2),
        (NF9_PROTOCOL, 1),
        (NF9_TCP_FLAGS, 1),
        (NF9_IP_PROTOCOL_VERSION, 1),
        (NF9_TOS, 1),
        (NF9_ICMP_TYPE, 2),
        (NF9_SRC_VLAN, 2),
    ];
    for &(t, l) in &v4_fields {
        packet.write_u16::<BigEndian>(t).unwrap();
        packet.write_u16::<BigEndian>(l).unwrap();
    }

    // 2. Write IPv6 Template (flowset_id=0, length=4+4+16*4 = 72)
    packet.write_u16::<BigEndian>(NF9_TEMPLATE_SET_ID).unwrap();
    packet.write_u16::<BigEndian>(72).unwrap();
    packet.write_u16::<BigEndian>(NF9_SOFTFLOWD_V6_TEMPLATE_ID).unwrap();
    packet.write_u16::<BigEndian>(16).unwrap();

    let v6_fields = [
        (NF9_IPV6_SRC_ADDR, 16),
        (NF9_IPV6_DST_ADDR, 16),
        (NF9_LAST_SWITCHED, 4),
        (NF9_FIRST_SWITCHED, 4),
        (NF9_IN_BYTES, 4),
        (NF9_IN_PACKETS, 4),
        (NF9_IF_INDEX_IN, 4),
        (NF9_IF_INDEX_OUT, 4),
        (NF9_L4_SRC_PORT, 2),
        (NF9_L4_DST_PORT, 2),
        (NF9_PROTOCOL, 1),
        (NF9_TCP_FLAGS, 1),
        (NF9_IP_PROTOCOL_VERSION, 1),
        (NF9_TOS, 1),
        (NF9_ICMP_TYPE, 2),
        (NF9_SRC_VLAN, 2),
    ];
    for &(t, l) in &v6_fields {
        packet.write_u16::<BigEndian>(t).unwrap();
        packet.write_u16::<BigEndian>(l).unwrap();
    }

    // 3. Write Options Template (flowset_id=1, length=4+4+4+4+2*4 = 24)
    packet.write_u16::<BigEndian>(NF9_OPTION_TEMPLATE_SET_ID).unwrap();
    packet.write_u16::<BigEndian>(24).unwrap();
    packet.write_u16::<BigEndian>(NF9_SOFTFLOWD_OPTION_TEMPLATE_ID).unwrap();
    packet.write_u16::<BigEndian>(4).unwrap(); // Scope length in bytes
    packet.write_u16::<BigEndian>(8).unwrap(); // Options length in bytes
    // Scope field (Interface Index)
    packet.write_u16::<BigEndian>(NFLOW9_OPTION_SCOPE_INTERFACE).unwrap();
    packet.write_u16::<BigEndian>(4).unwrap();
    // Option fields
    packet.write_u16::<BigEndian>(NFLOW9_SAMPLING_INTERVAL).unwrap();
    packet.write_u16::<BigEndian>(4).unwrap();
    packet.write_u16::<BigEndian>(NFLOW9_SAMPLING_ALGORITHM).unwrap();
    packet.write_u16::<BigEndian>(1).unwrap();
    // Padding to 32 bits
    packet.write_u8(0).unwrap();
    packet.write_u16::<BigEndian>(0).unwrap();
}

fn write_option_data(packet: &mut Vec<u8>, ifidx: u16, sample_rate: u32) {
    // Flowset ID = 256, length = 4 + 4 + 4 + 1 + 3 = 16
    packet.write_u16::<BigEndian>(NF9_SOFTFLOWD_OPTION_TEMPLATE_ID).unwrap();
    packet.write_u16::<BigEndian>(16).unwrap();
    packet.write_u32::<BigEndian>(ifidx as u32).unwrap();
    packet.write_u32::<BigEndian>(sample_rate).unwrap();
    packet.write_u8(1).unwrap(); // Sampling algorithm: Systematic count-based
    packet.write_u8(0).unwrap(); // Pad
    packet.write_u8(0).unwrap(); // Pad
    packet.write_u8(0).unwrap(); // Pad
}

pub fn send_netflow_v9(sp: SendParameter) -> i32 {
    let now = get_active_now(sp.param);
    let uptime_ms = now.sub_ms(&sp.param.system_boot_time);

    let mut packet = Vec::with_capacity(1500);
    let mut flows_in_packet = 0;
    let mut num_packets = 0;
    let mut offset_to_flow_count = 0;
    let mut current_template_id = 0;
    let mut offset_to_flowset_len = 0;
    let mut flowset_start_offset = 0;

    let target_flows = sp.flows;
    let ifidx = sp.ifidx;

    // Check if we need to send templates (periodically)
    let mut send_templates_now = false;
    unsafe {
        if PKTS_UNTIL_TEMPLATE <= 0 {
            send_templates_now = true;
            PKTS_UNTIL_TEMPLATE = 16;
        }
        PKTS_UNTIL_TEMPLATE -= 1;
    }

    if send_templates_now {
        // Send a dedicated packet with templates and options data
        packet.clear();
        packet.write_u16::<BigEndian>(9).unwrap(); // Version
        packet.write_u16::<BigEndian>(0).unwrap(); // Flowset count (will fill)
        packet.write_u32::<BigEndian>(uptime_ms).unwrap();
        packet.write_u32::<BigEndian>(now.tv_sec as u32).unwrap();
        packet.write_u32::<BigEndian>(sp.param.packets_sent as u32).unwrap(); // Package seq
        packet.write_u32::<BigEndian>(0).unwrap(); // Source ID

        write_templates(&mut packet);
        if sp.param.sample_rate > 0 {
            write_option_data(&mut packet, ifidx, sp.param.sample_rate);
        }

        // Set flowset count to 3 (or 4 if sample rate > 0)
        let num_sets = if sp.param.sample_rate > 0 { 4 } else { 3 };
        packet[2] = (num_sets >> 8) as u8;
        packet[3] = (num_sets & 0xFF) as u8;

        let mut sent = 0;
        let _ = sp.target.send_multi_destinations(&packet, &mut sent);
        sp.param.packets_sent += 1;
        packet.clear();
    }

    for flow in target_flows {
        let is_v6 = flow.key.af == 10;
        let flow_template_id = if is_v6 { NF9_SOFTFLOWD_V6_TEMPLATE_ID } else { NF9_SOFTFLOWD_V4_TEMPLATE_ID };

        for dir in 0..2 {
            if flow.octets[dir] == 0 {
                continue;
            }

            // Limit package size
            if packet.len() >= 1400 || (flows_in_packet > 0 && current_template_id != flow_template_id) {
                // Finalize old flowset length
                let flowset_len = (packet.len() - flowset_start_offset) as u16;
                packet[offset_to_flowset_len] = (flowset_len >> 8) as u8;
                packet[offset_to_flowset_len + 1] = (flowset_len & 0xFF) as u8;

                if let Err(e) = send_packet(&mut packet, &sp, offset_to_flow_count) {
                    log::error!("Failed to send netflow v9 packet: {}", e);
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
                packet.write_u16::<BigEndian>(9).unwrap(); // Version
                offset_to_flow_count = packet.len();
                packet.write_u16::<BigEndian>(0).unwrap(); // Flowset count
                packet.write_u32::<BigEndian>(uptime_ms).unwrap();
                packet.write_u32::<BigEndian>(now.tv_sec as u32).unwrap();
                packet.write_u32::<BigEndian>(sp.param.packets_sent as u32).unwrap();
                packet.write_u32::<BigEndian>(0).unwrap(); // Source ID
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
                packet.write_u16::<BigEndian>(0).unwrap(); // Flowset length (fill in later)

                current_template_id = flow_template_id;
                // Increment flowset count in header
                let flowset_count = BigEndian::read_u16(&packet[offset_to_flow_count..offset_to_flow_count + 2]) + 1;
                packet[offset_to_flow_count] = (flowset_count >> 8) as u8;
                packet[offset_to_flow_count + 1] = (flowset_count & 0xFF) as u8;
            }

            // Write Flow Data
            if is_v6 {
                // Source & Destination Address
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

            // Common statistics
            let flow_start_ms = flow.flow_start.sub_ms(&sp.param.system_boot_time);
            let flow_last_ms = flow.flow_last.sub_ms(&sp.param.system_boot_time);
            packet.write_u32::<BigEndian>(flow_last_ms).unwrap();
            packet.write_u32::<BigEndian>(flow_start_ms).unwrap();
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
            
            // ICMP type/code (port contains type * 256 + code in canonical endianness)
            packet.write_u16::<BigEndian>(flow.key.port[dir ^ 1].to_be()).unwrap();
            // VLAN ID
            packet.write_u16::<BigEndian>(flow.key.vlanid[dir]).unwrap();

            flows_in_packet += 1;
        }
    }

    if flows_in_packet > 0 {
        // Close last flowset
        let flowset_len = (packet.len() - flowset_start_offset) as u16;
        packet[offset_to_flowset_len] = (flowset_len >> 8) as u8;
        packet[offset_to_flowset_len + 1] = (flowset_len & 0xFF) as u8;

        if let Err(e) = send_packet(&mut packet, &sp, offset_to_flow_count) {
            log::error!("Failed to send netflow v9 leftovers: {}", e);
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

fn send_packet(packet: &mut [u8], sp: &SendParameter, _offset_to_flow_count: usize) -> std::io::Result<()> {
    let mut sent = 0;
    sp.target.send_multi_destinations(packet, &mut sent)
}
