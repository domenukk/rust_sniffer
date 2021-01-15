use pnet::datalink;
use pnet_datalink::{
    self,
    Channel::{self, Ethernet},
    MacAddr, NetworkInterface,
};
use pnet_packet::{
    arp::ArpPacket,
    ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::{Ipv4Flags, Ipv4Packet, MutableIpv4Packet},
    ipv6::Ipv6Packet,
    tcp::{MutableTcpPacket, TcpFlags, TcpOption, TcpPacket},
    MutablePacket, Packet,
};
use std::{
    env,
    io::{self, Write},
    net::{IpAddr, Ipv4Addr},
    process,
};
use IpNextHeaderProtocols::Tcp;

/// parse the tcp flags to a human-readable form
fn stringify_flags(flags: u16) -> String {
    let mut flag_strs = vec![];
    for (flag, name) in &[
        (TcpFlags::SYN, "SYN"),
        (TcpFlags::ACK, "ACK"),
        (TcpFlags::URG, "URGENT"),
        (TcpFlags::NS, "NS"),
        (TcpFlags::PSH, "PUSH"),
        (TcpFlags::RST, "RESET"),
        (TcpFlags::FIN, "FIN"),
    ] {
        if flags & flag != 0 {
            flag_strs.push(*name)
        }
    }
    flag_strs.join("|")
}

pub fn build_tcp_packet(
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    tcp_flags: u16,
    payload: &[u8],
) -> [u8; 1500] {
    let mut tmp_packet = [0u8; 1500];
    const ETHERNET_HEADER_LEN: usize = 14;
    const IPV4_HEADER_LEN: usize = 20;

    // Setup Ethernet header
    {
        let mut eth_header =
            MutableEthernetPacket::new(&mut tmp_packet[..ETHERNET_HEADER_LEN]).unwrap();

        //eth_header.set_destination(MacAddr::broadcast());
        eth_header.set_source(src_mac);
        eth_header.set_destination(dst_mac);
        eth_header.set_ethertype(EtherTypes::Ipv4);
    }

    // Setup IP header
    {
        let mut ip_header = MutableIpv4Packet::new(
            &mut tmp_packet[ETHERNET_HEADER_LEN..(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)],
        )
        .unwrap();
        ip_header.set_header_length(69);
        ip_header.set_total_length(52);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_header.set_source(src_ip);
        ip_header.set_destination(dst_ip);
        ip_header.set_identification(rand::random::<u16>());
        ip_header.set_ttl(64);
        ip_header.set_version(4);
        ip_header.set_flags(Ipv4Flags::DontFragment);

        let checksum = pnet_packet::ipv4::checksum(&ip_header.to_immutable());
        ip_header.set_checksum(checksum);
    }

    // Setup TCP header
    {
        let mut tcp_header =
            MutableTcpPacket::new(&mut tmp_packet[(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)..])
                .unwrap();

        tcp_header.set_source(src_port);
        tcp_header.set_destination(dst_port);

        tcp_header.set_flags(tcp_flags);
        tcp_header.set_window(64240);
        tcp_header.set_data_offset(8);
        tcp_header.set_urgent_ptr(0);
        tcp_header.set_sequence(seq_num);
        tcp_header.set_acknowledgement(ack_num);

        tcp_header.set_options(&[
            TcpOption::mss(1460),
            TcpOption::sack_perm(),
            TcpOption::nop(),
            TcpOption::nop(),
            TcpOption::wscale(7),
        ]);

        tcp_header.set_payload(payload);

        let checksum =
            pnet_packet::tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ip, &dst_ip);
        tcp_header.set_checksum(checksum);
    }

    tmp_packet
}

fn yolo_send(interface_name: &str, buf: &[u8]) {
    let interfaces = pnet_datalink::interfaces();

    for interface in interfaces.iter() {
        let iface_ip = interface.ips.iter().next().map(|x| match x.ip() {
            IpAddr::V4(ipv4) => Some(ipv4),
            _ => panic!("ERR - Interface IP is IPv6 (or unknown) which is not currently supported"),
        });

        println!(
            "Interface name: {:?}\nInterface MAC: {:?}\nInterface IP: {:?}\n",
            &interface.name,
            &interface.mac.unwrap(),
            iface_ip
        )
    }

    let interfaces_name_match = |iface: &NetworkInterface| iface.name == interface_name;
    let interface = interfaces
        .into_iter()
        .filter(interfaces_name_match)
        .next()
        .expect(&format!(
            "could not find interface by name {}",
            interface_name
        ));

    let iface_ip = match interface
        .ips
        .iter()
        .nth(0)
        .expect(&format!(
            "the interface {} does not have any IP addresses",
            interface
        ))
        .ip()
    {
        IpAddr::V4(ipv4) => ipv4,
        _ => panic!("ERR - Interface IP is IPv6 (or unknown) which is not currently supported"),
    };

    let (mut tx, _) = match pnet_datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };

    tx.send_to(buf, None);
}

fn handle_tcp_packet(
    interface_name: &str,
    direction: &Direction,
    own_mac: MacAddr,
    other_mac: MacAddr,
    own_ip: Ipv4Addr,
    other_ip: Ipv4Addr,
    tcp: &TcpPacket,
) {
    let our_port = 80;
    let new_dst_port = 8090;
    // filter by dst port
    if tcp.get_destination() == our_port {
        let flags = tcp.get_flags();
        // Oh boi, we received a syn. Respond.
        if flags & TcpFlags::SYN != 0 {
            // Answer with SYN|ACK, but to a different port...
            let new_packet = build_tcp_packet(
                own_mac,
                other_mac,
                own_ip,
                other_ip,
                our_port,
                tcp.get_source(), //new_dst_port,
                1337,
                tcp.get_sequence() + 1,
                flags | TcpFlags::ACK,
                &[],
            );
            yolo_send(interface_name, &new_packet);
            //new_packet
        }
        println!(
            "[{}]: TCP Packet: ({:#?}) flags: {:#?}",
            interface_name,
            &tcp,
            stringify_flags(flags),
        );
    } else if tcp.get_source() == 8080 {
        // print outgoing, for debug purposes
        let flags = tcp.get_flags();
        println!(
            "[{}]: (Potentially) outgoing TCP Packet: ({:#?}) flags: {:#?}",
            interface_name,
            &tcp,
            stringify_flags(flags),
        );
    }
}

fn handle_ipv4_packet(
    interface_name: &str,
    direction: &Direction,
    own_mac: MacAddr,
    other_mac: MacAddr,
    own_ip: Ipv4Addr,
    ethernet: &EthernetPacket,
) -> Result<(), io::Error> {
    let header: Option<Ipv4Packet> = Ipv4Packet::new(ethernet.payload());

    if let Some(header) = header {
        let other_ip = match direction {
            Direction::In => IpAddr::V4(header.get_source()),
            Direction::Out => IpAddr::V4(header.get_destination()),
        };
        let other_ip = match other_ip {
            IpAddr::V4(other_ip) => other_ip,
            _ => panic!("WHAT! NO V4"),
        };

        match header.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => handle_tcp_packet(
                interface_name,
                direction,
                own_mac,
                other_mac,
                own_ip,
                other_ip,
                &TcpPacket::new(header.payload()).unwrap(),
            ),
            _ => (), /*println!(
                         "[{}]: Unknown {} packet: {} > {}; protocol: {:?} length: {}",
                         interface_name,
                         match source {
                             IpAddr::V4(..) => "IPv4",
                             _ => "IPv6",
                         },
                         source,
                         destination,
                         protocol,
                         packet.len()
                     )*/
        }
    }
    Ok(())
}

/*
        handle_transport_protocol(
            interface_name,
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
        );
    }
}*/

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// If we sent or recvd this packet
enum Direction {
    In,
    Out,
}

fn handle_ethernet_frame(interface: &NetworkInterface, ethernet: &EthernetPacket) {
    let interface_name = &interface.name[..];
    let own_mac = interface.mac.expect("No MAC assigned to interface!");
    let ip = interface
        .ips
        .iter()
        .find(|x| x.is_ipv4())
        .expect("msg")
        .ip();
    match ip {
        IpAddr::V4(own_ip) => {
            let src = ethernet.get_source();

            let (direction, other_mac) = if src == own_mac {
                (Direction::Out, ethernet.get_destination())
            } else {
                (Direction::In, src)
            };

            match ethernet.get_ethertype() {
                EtherTypes::Ipv4 => {
                    handle_ipv4_packet(
                        interface_name,
                        &direction,
                        own_mac,
                        other_mac,
                        own_ip,
                        ethernet,
                    )
                    .unwrap();
                }
                _ => (),
            };
        }
        _ => (),
    }
}

fn main() {
    println!(
        "Welcome to our faux TCP stack.\n\
        Make sure you DROP all outgoing RST packages.\n\
        On Linux, use: sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP"
    );
    let iface_name = match env::args().nth(1) {
        Some(n) => n,
        None => {
            writeln!(io::stderr(), "USAGE: natrav <NETWORK INTERFACE>").unwrap();
            process::exit(1);
        }
    };
    let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap_or_else(|| panic!("No such network interface: {}", iface_name));

    let mac = interface.mac.expect("No MAC assigned to interface!");
    let ip = interface
        .ips
        .iter()
        .find(|x| x.is_ipv4())
        .expect("msg")
        .ip();

    // Create a channel to receive on
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packetdump: unhandled channel type: {}"),
        Err(e) => panic!("packetdump: unable to create channel: {}", e),
    };

    loop {
        let mut buf: [u8; 1600] = [0u8; 1600];
        let mut fake_ethernet_frame = MutableEthernetPacket::new(&mut buf[..]).unwrap();
        match rx.next() {
            Ok(packet) => {
                let payload_offset;
                if cfg!(any(target_os = "macos", target_os = "ios"))
                    && interface.is_up()
                    && !interface.is_broadcast()
                    && ((!interface.is_loopback() && interface.is_point_to_point())
                        || interface.is_loopback())
                {
                    if interface.is_loopback() {
                        // The pnet code for BPF loopback adds a zero'd out Ethernet header
                        payload_offset = 14;
                    } else {
                        // Maybe is TUN interface
                        payload_offset = 0;
                    }
                    if packet.len() > payload_offset {
                        let version = Ipv4Packet::new(&packet[payload_offset..])
                            .unwrap()
                            .get_version();
                        if version == 4 {
                            fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_ethertype(EtherTypes::Ipv4);
                            fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                            handle_ethernet_frame(&interface, &fake_ethernet_frame.to_immutable());
                            continue;
                        } else if version == 6 {
                            fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_ethertype(EtherTypes::Ipv6);
                            fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                            handle_ethernet_frame(&interface, &fake_ethernet_frame.to_immutable());
                            continue;
                        }
                    }
                }
                handle_ethernet_frame(&interface, &EthernetPacket::new(packet).unwrap());
            }
            Err(e) => panic!("packetdump: unable to receive packet: {}", e),
        }
    }
}

/*
fn main() {
    send_tcp_packets("192.168.178.1".parse().unwrap(), "eth0", 100);
}
*/
