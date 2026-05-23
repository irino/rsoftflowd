use std::io::Write;
use byteorder::{BigEndian, WriteBytesExt};
use crate::common::{Flow, TimeVal};
use crate::exporter::{SendParameter, get_active_now};

pub fn send_netflow_v5(mut sp: SendParameter) -> i32 {
    let now = get_active_now(sp.param);
    let uptime_ms = now.sub_ms(&sp.param.system_boot_time);

    let mut packet = Vec::with_capacity(1500);
    let mut flows_in_packet = 0;
    let mut num_packets = 0;
    let mut offset_to_flow_count = 0;

    let target_flows = sp.flows;
    let ifidx = sp.ifidx;

    for flow in target_flows {
        if flow.key.af != 2 {
            // NetFlow v5 does not support IPv6
            continue;
        }

        // Each bidirectional flow has potentially two directions to export (src->dst and dst->src)
        for dir in 0..2 {
            if flow.octets[dir] == 0 {
                continue;
            }

            if flows_in_packet >= 30 {
                // Send current packet
                if let Err(e) = send_packet(&mut packet, &sp, offset_to_flow_count, flows_in_packet) {
                    log::error!("Failed to send netflow v5 packet: {}", e);
                    sp.param.flows_dropped += flows_in_packet as u64;
                    return -1;
                }
                sp.param.records_sent += flows_in_packet as u64;
                sp.param.flows_exported += flows_in_packet as u64;
                flows_in_packet = 0;
                num_packets += 1;
            }

            if flows_in_packet == 0 {
                packet.clear();
                // 1. Write Header (24 bytes)
                packet.write_u16::<BigEndian>(5).unwrap(); // Version
                offset_to_flow_count = packet.len();
                packet.write_u16::<BigEndian>(0).unwrap(); // Flows count (fill in later)
                packet.write_u32::<BigEndian>(uptime_ms).unwrap();
                packet.write_u32::<BigEndian>(now.tv_sec as u32).unwrap();
                packet.write_u32::<BigEndian>((now.tv_usec * 1000) as u32).unwrap();
                packet.write_u32::<BigEndian>((sp.param.flows_exported + sp.param.records_sent) as u32).unwrap(); // Sequence
                packet.write_u8(0).unwrap(); // Engine type
                packet.write_u8(0).unwrap(); // Engine ID
                
                let mut sampling = 0u16;
                if sp.param.sample_rate > 0 {
                    sampling = 0x4000 | (sp.param.sample_rate & 0x3FFF) as u16;
                }
                packet.write_u16::<BigEndian>(sampling).unwrap();
            }

            // 2. Write Flow Record (48 bytes)
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
            packet.write_u32::<BigEndian>(0).unwrap(); // Nexthop IP
            packet.write_u16::<BigEndian>(ifidx).unwrap(); // Input interface
            packet.write_u16::<BigEndian>(ifidx).unwrap(); // Output interface
            packet.write_u32::<BigEndian>(flow.packets[dir]).unwrap();
            packet.write_u32::<BigEndian>(flow.octets[dir]).unwrap();

            let flow_start_ms = flow.flow_start.sub_ms(&sp.param.system_boot_time);
            let flow_last_ms = flow.flow_last.sub_ms(&sp.param.system_boot_time);
            packet.write_u32::<BigEndian>(flow_start_ms).unwrap();
            packet.write_u32::<BigEndian>(flow_last_ms).unwrap();

            packet.write_u16::<BigEndian>(flow.key.port[dir].to_be()).unwrap();
            packet.write_u16::<BigEndian>(flow.key.port[dir ^ 1].to_be()).unwrap();
            packet.write_u8(0).unwrap(); // Pad
            packet.write_u8(flow.tcp_flags[dir]).unwrap();
            packet.write_u8(flow.key.protocol).unwrap();
            packet.write_u8(flow.tos[dir]).unwrap();
            packet.write_u16::<BigEndian>(0).unwrap(); // Source AS
            packet.write_u16::<BigEndian>(0).unwrap(); // Dest AS
            packet.write_u8(0).unwrap(); // Source mask
            packet.write_u8(0).unwrap(); // Dest mask
            packet.write_u16::<BigEndian>(0).unwrap(); // Pad2

            flows_in_packet += 1;
        }
    }

    // Send leftovers
    if flows_in_packet > 0 {
        if let Err(e) = send_packet(&mut packet, &sp, offset_to_flow_count, flows_in_packet) {
            log::error!("Failed to send netflow v5 packet leftovers: {}", e);
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

fn send_packet(
    packet: &mut [u8],
    sp: &SendParameter,
    offset_to_flow_count: usize,
    flows_count: u16,
) -> std::io::Result<()> {
    // Fill flow count in big endian
    packet[offset_to_flow_count] = (flows_count >> 8) as u8;
    packet[offset_to_flow_count + 1] = (flows_count & 0xFF) as u8;

    let mut sent = 0;
    sp.target.send_multi_destinations(packet, &mut sent)
}
