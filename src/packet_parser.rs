use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use byteorder::{ByteOrder, BigEndian, LittleEndian};
use crate::common::{TrackLevel, TimeVal};

// Standard Datalink Types
pub const DLT_EN10MB: i32 = 1;
pub const DLT_PPP: i32 = 5;
pub const DLT_LINUX_SLL: i32 = 113;
pub const DLT_RAW: i32 = 12;
pub const DLT_NULL: i32 = 0;
pub const DLT_LOOP: i32 = 108;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;

// IPv6 Extension Headers
const IPPROTO_HOPOPTS: u8 = 0;
const IPPROTO_ROUTING: u8 = 43;
const IPPROTO_FRAGMENT: u8 = 44;
const IPPROTO_DSTOPTS: u8 = 60;

#[derive(Debug)]
pub struct ParsedPacket {
    pub af: u16, // libc::AF_INET = 2, libc::AF_INET6 = 10
    pub protocol: u8,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub vlan_id: u16,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub mpls_labels: Vec<u32>,
    pub tcp_flags: u8,
    pub tos: u8,
    pub is_frag: bool,
    pub is_first: bool,
    pub ip6_flowlabel: u32,
    pub length: u32,
    pub timestamp: TimeVal,
}

pub fn parse_packet(
    linktype: i32,
    pkt: &[u8],
    caplen: u32,
    orig_len: u32,
    track_level: TrackLevel,
    timestamp: TimeVal,
) -> Option<ParsedPacket> {
    let caplen = caplen as usize;
    let orig_len = orig_len as usize;
    let mut offset: usize = 0;
    let mut vlan_id = 0;
    let mut mpls_labels = Vec::new();
    let mut src_mac = [0; 6];
    let mut dst_mac = [0; 6];
    let mut af = 0;

    // 1. Parse Datalink Layer
    match linktype {
        DLT_EN10MB => {
            if caplen < 14 {
                return None;
            }
            dst_mac.copy_from_slice(&pkt[0..6]);
            src_mac.copy_from_slice(&pkt[6..12]);
            let mut ethertype = BigEndian::read_u16(&pkt[12..14]);
            offset = 14;

            // Handle VLAN tags (0x8100 = 802.1Q, 0x88a8 = 802.1ad)
            while ethertype == 0x8100 || ethertype == 0x88a8 {
                if caplen < offset + 4 {
                    return None;
                }
                let tci = BigEndian::read_u16(&pkt[offset..offset+2]);
                vlan_id = tci & 0x0FFF;
                ethertype = BigEndian::read_u16(&pkt[offset+2..offset+4]);
                offset += 4;
            }

            // Handle MPLS (0x8847)
            if ethertype == 0x8847 {
                loop {
                    if caplen < offset + 4 {
                        return None;
                    }
                    let shim = BigEndian::read_u32(&pkt[offset..offset+4]);
                    mpls_labels.push(shim);
                    offset += 4;
                    // Check Bottom of Stack bit (bit 8 from right, shifted by 8)
                    if (shim & 0x00000100) != 0 {
                        break;
                    }
                }
                // Try to infer payload IP version
                if caplen < offset + 1 {
                    return None;
                }
                let ip_ver = (pkt[offset] & 0xF0) >> 4;
                if ip_ver == 4 {
                    af = 2; // AF_INET
                } else if ip_ver == 6 {
                    af = 10; // AF_INET6
                } else {
                    return None;
                }
            } else if ethertype == 0x0800 {
                af = 2; // AF_INET
            } else if ethertype == 0x86dd {
                af = 10; // AF_INET6
            } else {
                return None;
            }
        }
        DLT_RAW => {
            if caplen < 1 {
                return None;
            }
            let ip_ver = (pkt[0] & 0xF0) >> 4;
            if ip_ver == 4 {
                af = 2;
            } else if ip_ver == 6 {
                af = 10;
            } else {
                return None;
            }
            offset = 0;
        }
        DLT_NULL | DLT_LOOP => {
            if caplen < 4 {
                return None;
            }
            let family = if linktype == DLT_NULL {
                // Null loopback is local host byte order
                if cfg!(target_endian = "big") {
                    BigEndian::read_u32(&pkt[0..4])
                } else {
                    LittleEndian::read_u32(&pkt[0..4])
                }
            } else {
                // Loop is always big endian
                BigEndian::read_u32(&pkt[0..4])
            };
            // Map family to AF
            if family == 2 {
                af = 2;
            } else if family == 10 || family == 24 || family == 28 || family == 30 {
                // Loopback IPv6 families vary across OS, check standard ones
                af = 10;
            } else {
                return None;
            }
            offset = 4;
        }
        DLT_LINUX_SLL => {
            if caplen < 16 {
                return None;
            }
            let protocol = BigEndian::read_u16(&pkt[14..16]);
            offset = 16;
            if protocol == 0x0800 {
                af = 2;
            } else if protocol == 0x86dd {
                af = 10;
            } else {
                return None;
            }
        }
        _ => return None,
    }

    if caplen < offset {
        return None;
    }

    let mut src_ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
    let mut dst_ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
    let mut protocol = 0;
    let mut tos = 0;
    let mut is_frag = false;
    let mut is_first = true;
    let mut ip6_flowlabel = 0;
    let mut next_header_offset = offset;

    // 2. Parse IP Layer
    if af == 2 {
        // IPv4
        if caplen < offset + 20 {
            return None;
        }
        let version = (pkt[offset] & 0xF0) >> 4;
        if version != 4 {
            return None;
        }
        let ihl = ((pkt[offset] & 0x0F) * 4) as usize;
        if caplen < offset + ihl {
            return None;
        }
        tos = pkt[offset + 1];
        protocol = pkt[offset + 9];

        let ip_src_bytes = &pkt[offset + 12..offset + 16];
        let ip_dst_bytes = &pkt[offset + 16..offset + 20];
        src_ip = IpAddr::V4(Ipv4Addr::new(ip_src_bytes[0], ip_src_bytes[1], ip_src_bytes[2], ip_src_bytes[3]));
        dst_ip = IpAddr::V4(Ipv4Addr::new(ip_dst_bytes[0], ip_dst_bytes[1], ip_dst_bytes[2], ip_dst_bytes[3]));

        let frag_field = BigEndian::read_u16(&pkt[offset + 6..offset + 8]);
        let frag_offset = frag_field & 0x1FFF;
        let more_frags = (frag_field & 0x2000) != 0;

        is_frag = frag_offset != 0 || more_frags;
        is_first = frag_offset == 0;

        next_header_offset = offset + ihl;
    } else if af == 10 {
        // IPv6
        if caplen < offset + 40 {
            return None;
        }
        let version = (pkt[offset] & 0xF0) >> 4;
        if version != 6 {
            return None;
        }

        let flow_field = BigEndian::read_u32(&pkt[offset..offset + 4]);
        tos = ((flow_field & 0x0FF00000) >> 20) as u8;
        ip6_flowlabel = flow_field & 0x000FFFFF;

        let mut ip_src_bytes = [0; 16];
        let mut ip_dst_bytes = [0; 16];
        ip_src_bytes.copy_from_slice(&pkt[offset + 8..offset + 24]);
        ip_dst_bytes.copy_from_slice(&pkt[offset + 24..offset + 40]);
        src_ip = IpAddr::V6(Ipv6Addr::from(ip_src_bytes));
        dst_ip = IpAddr::V6(Ipv6Addr::from(ip_dst_bytes));

        let mut nxt = pkt[offset + 6];
        next_header_offset = offset + 40;

        // Traverse extension headers
        loop {
            let remain = caplen.saturating_sub(next_header_offset);
            if nxt == IPPROTO_HOPOPTS || nxt == IPPROTO_ROUTING || nxt == IPPROTO_DSTOPTS {
                if remain < 2 {
                    break;
                }
                let ext_len = ((pkt[next_header_offset + 1] as usize + 1) << 3) as usize;
                if remain < ext_len {
                    break;
                }
                nxt = pkt[next_header_offset];
                next_header_offset += ext_len;
            } else if nxt == IPPROTO_FRAGMENT {
                if remain < 8 {
                    break;
                }
                is_frag = true;
                let frag_offlg = BigEndian::read_u16(&pkt[next_header_offset + 2..next_header_offset + 4]);
                let frag_offset = frag_offlg & 0xFFF8;
                if frag_offset != 0 {
                    is_first = false;
                }
                nxt = pkt[next_header_offset];
                next_header_offset += 8;
            } else {
                break;
            }
        }
        protocol = nxt;
    } else {
        return None;
    }

    let mut src_port = 0;
    let mut dst_port = 0;
    let mut tcp_flags = 0;

    // 3. Parse Transport Layer (Only if it's the first fragment)
    if is_first && track_level >= TrackLevel::IpProtoPort {
        let remain = caplen.saturating_sub(next_header_offset);
        match protocol {
            IPPROTO_TCP => {
                if remain >= 20 {
                    src_port = BigEndian::read_u16(&pkt[next_header_offset..next_header_offset + 2]);
                    dst_port = BigEndian::read_u16(&pkt[next_header_offset + 2..next_header_offset + 4]);
                    tcp_flags = pkt[next_header_offset + 13];
                }
            }
            IPPROTO_UDP => {
                if remain >= 8 {
                    src_port = BigEndian::read_u16(&pkt[next_header_offset..next_header_offset + 2]);
                    dst_port = BigEndian::read_u16(&pkt[next_header_offset + 2..next_header_offset + 4]);
                }
            }
            IPPROTO_ICMP => {
                if remain >= 2 {
                    let icmp_type = pkt[next_header_offset] as u16;
                    let icmp_code = pkt[next_header_offset + 1] as u16;
                    src_port = 0;
                    // Encode ICMP type * 256 + code like Cisco
                    dst_port = (icmp_type * 256 + icmp_code).to_be();
                }
            }
            IPPROTO_ICMPV6 => {
                if remain >= 2 {
                    let icmp_type = pkt[next_header_offset] as u16;
                    let icmp_code = pkt[next_header_offset + 1] as u16;
                    src_port = 0;
                    dst_port = (icmp_type * 256 + icmp_code).to_be();
                }
            }
            _ => {}
        }
    }

    Some(ParsedPacket {
        af,
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        vlan_id,
        src_mac,
        dst_mac,
        mpls_labels,
        tcp_flags,
        tos,
        is_frag,
        is_first,
        ip6_flowlabel,
        length: orig_len.saturating_sub(offset) as u32,
        timestamp,
    })
}
