mod net;
// use std::net::{TcpListener, TcpStream};
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::{ Icmp };
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::{ Packet, MutablePacket};
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{transport_channel, udp_packet_iter, tcp_packet_iter};
use pnet::util::MacAddr;
use std::env;
use std::f32;
use std::io::{self, Read, Write, BufRead};
use std::net::IpAddr;
use std::net::{TcpListener, TcpStream, Shutdown};
use std::process;
use std::str::from_utf8;

// https://github.com/libpnet/libpnet/blob/master/examples/packetdump.rs

fn to_float (data: &[u8;50], size: usize) -> f32 {

    let s = from_utf8(&data[0..size]).unwrap();
    let mut s = s.to_string ();
    let len = s.len();
    s.truncate(len - 1);

    // 1f32
    s.parse::<f32>().unwrap()
}

fn to_int (data: &[u8;50], size: usize) -> i32 {

    let s = from_utf8(&data[0..size]).unwrap();
    let mut s = s.to_string ();
    let len = s.len();
    s.truncate(len - 1);

    // 1f32
    s.parse::<i32>().unwrap()
}

// fn send_icmp () {
//     let mut saddr = "".to_string();
//     // let mut rate = 0;
//     let mut identifier = 1337;
//     let mut sequence_number = 1;

//     let sockv4 = net::new_icmpv4_socket().expect("Could not create socket (v4)");
//     if !saddr.is_empty() {
//         net::bind_to_ip(sockv4, &saddr).expect("Could not bind socket to source address");
//     }

//     let sockv6 = net::new_icmpv6_socket().expect("Could not create socket (v6)");

//     // Create new ICMP-header (IPv4 and IPv6)
//     let icmp4header = net::ICMP4Header::echo_request(identifier, sequence_number).to_byte_array();
//     let icmp6header = net::ICMP6Header::echo_request(identifier, sequence_number).to_byte_array();

//     // Send packet

//     let dest = "192.168.1.12";

//     let result = net::send_packet(sockv4, sockv6, dest, &icmp4header, &icmp6header);
//     if let Err(msg) = result {
//         println!("Could not send packet: {}", msg);
//     }

// }

fn handle_tcp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {

        // TODO : that's us!
        if (tcp.get_destination() == 3002) {

            println!(
                "[{}]: TCP Packet: {}:{} > {}:{}; length: {}",
                interface_name,
                source,
                tcp.get_source(),
                destination,
                tcp.get_destination(),
                packet.len()
            );
        }

    } else {
        println!("[{}]: Malformed TCP Packet", interface_name);
    }
}

fn handle_icmp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let icmp_packet = IcmpPacket::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {
                let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                println!(
                    "[{}]: ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                    interface_name,
                    source,
                    destination,
                    echo_reply_packet.get_sequence_number(),
                    echo_reply_packet.get_identifier()
                );
            }
            IcmpTypes::EchoRequest => {
                let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                println!(
                    "[{}]: ICMP echo request {} -> {} (seq={:?}, id={:?})",
                    interface_name,
                    source,
                    destination,
                    echo_request_packet.get_sequence_number(),
                    echo_request_packet.get_identifier()
                );
            }
            _ => println!(
                "[{}]: ICMP packet {} -> {} (type={:?})",
                interface_name,
                source,
                destination,
                icmp_packet.get_icmp_type()
            ),
        }
    } else {
        println!("[{}]: Malformed ICMP Packet", interface_name);
    }
}

fn handle_transport_protocol(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
) {
    match protocol {
        // IpNextHeaderProtocols::Udp => {
        //     handle_udp_packet(interface_name, source, destination, packet)
        // }
        IpNextHeaderProtocols::Tcp => {
            handle_tcp_packet(interface_name, source, destination, packet)
        }
        IpNextHeaderProtocols::Icmp => {
            handle_icmp_packet(interface_name, source, destination, packet)
        }
        // IpNextHeaderProtocols::Icmpv6 => {
        //     handle_icmpv6_packet(interface_name, source, destination, packet)
        // }
        _ => ()
        //     println!(
        //     "[{}]: Unknown {} packet: {} > {}; protocol: {:?} length: {}",
        //     interface_name,
        //     match source {
        //         IpAddr::V4(..) => "IPv4",
        //         _ => "IPv6",
        //     },
        //     source,
        //     destination,
        //     protocol,
        //     packet.len()
        // ),
    }
}

fn handle_ipv4_packet(interface_name: &str, ethernet: &EthernetPacket) {
    let header = Ipv4Packet::new(ethernet.payload());

    // println! ("ipv4 header: {:#?}", header);

    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
        );
    } else {
        println!("[{}]: Malformed IPv4 Packet", interface_name);
    }
}

fn handle_ethernet_frame(interface: &NetworkInterface, ethernet: &EthernetPacket) {

    // println! ("eth frame: {:#?}", ethernet);

    let interface_name = &interface.name[..];

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(interface_name, ethernet),
        // EtherTypes::Ipv6 => handle_ipv6_packet(interface_name, ethernet),
        // EtherTypes::Arp => handle_arp_packet(interface_name, ethernet),
        _ => println!(
            "[{}]: Unknown packet: {} > {}; ethertype: {:?} length: {}",
            interface_name,
            ethernet.get_source(),
            ethernet.get_destination(),
            ethernet.get_ethertype(),
            ethernet.packet().len()
        )
    }
}

// fn main() -> std::io::Result<()> {

//     let iface_name = "lo";
//     let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;

//     // Find the network interface with the provided name
//     let interfaces = datalink::interfaces();
//     let interface = interfaces
//         .into_iter()
//         .filter(interface_names_match)
//         .next()
//         .unwrap_or_else(|| panic!("No such network interface: {}", iface_name));

//     let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
//         Ok(Ethernet(tx, rx)) => (tx, rx),
//         Ok(_) => panic!("packetdump: unhandled channel type: {}"),
//         Err(e) => panic!("packetdump: unable to create channel: {}", e),
//     };

//     loop {
//         let mut buf: [u8; 1600] = [0u8; 1600];
//         let mut fake_ethernet_frame = MutableEthernetPacket::new(&mut buf[..]).unwrap();
//         match rx.next() {
//             Ok(packet) => {
//                 let payload_offset;
//                 if cfg!(any(target_os = "macos", target_os = "ios"))
//                     && interface.is_up()
//                     && !interface.is_broadcast()
//                     && ((!interface.is_loopback() && interface.is_point_to_point())
//                         || interface.is_loopback())
//                 {
//                     if interface.is_loopback() {
//                         // The pnet code for BPF loopback adds a zero'd out Ethernet header
//                         payload_offset = 14;
//                     } else {
//                         // Maybe is TUN interface
//                         payload_offset = 0;
//                     }
//                     if packet.len() > payload_offset {
//                         let version = Ipv4Packet::new(&packet[payload_offset..])
//                             .unwrap()
//                             .get_version();
//                         if version == 4 {
//                             fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
//                             fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
//                             fake_ethernet_frame.set_ethertype(EtherTypes::Ipv4);
//                             fake_ethernet_frame.set_payload(&packet[payload_offset..]);

//                             handle_ethernet_frame(&interface, &fake_ethernet_frame.to_immutable());
//                             continue;
//                         } else if version == 6 {
//                             fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
//                             fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
//                             fake_ethernet_frame.set_ethertype(EtherTypes::Ipv6);
//                             fake_ethernet_frame.set_payload(&packet[payload_offset..]);

//                             handle_ethernet_frame(&interface, &fake_ethernet_frame.to_immutable());
//                             continue;
//                         }
//                     }
//                 }

//                 handle_ethernet_frame(&interface, &EthernetPacket::new(packet).unwrap());

//             }
//             Err(e) => panic!("packetdump: unable to receive packet: {}", e),
//         }
//     }



//     // send_icmp ();

//     // let listener = TcpListener::bind("127.0.0.1:3002")?;

//     // // accept connections and process them serially
//     // for stream in listener.incoming() {
//     //     handle_incoming(stream?);
//     // }
//     Ok(())
// }


fn handle_incoming(mut stream: TcpStream) {

    println!("@handle incoming");

    let mut data = [0 as u8; 50];
    while match stream.read(&mut data) {
        Ok(size) => {
            println!("Received {} bytes", size);

            let v = to_int (&data, size);

            println!("value: {:#?}",  v);

            // TODO : send ICMP echo request
            // send_icmp ();

            true
        },
        Err(_) => {
            println!("An error occurred, terminating connection with {}", stream.peer_addr().unwrap());
            stream.shutdown(Shutdown::Both).unwrap();
            false
        }
    } {}

}

fn main() -> std::io::Result<()> {

    // send_icmp ();

    let listener = TcpListener::bind("127.0.0.1:3002")?;

    // accept connections and process them serially
    for stream in listener.incoming() {
        handle_incoming(stream?);
    }
    Ok(())
}

pub fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>())
}
