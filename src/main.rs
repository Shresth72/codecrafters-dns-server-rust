/*
DNS Server
    Header Structure (Stage 1)
    Question Section (Stage 2)
    Answer Section (Stage 3)
    Authority Section (Stage 4)
    Additional Section (Stage 5)
*/

#![allow(unused)]

use anyhow::Context;
use bytes::buf::Writer;
use bytes::{BufMut, BytesMut};
use nom::IResult;
use std::net::{SocketAddr, UdpSocket};

// Header Structure
// RFC Name	    Descriptive Name	    Length	    Description
// ID	        Packet Identifier	    16 bits	    A random identifier is assigned to query packets. Response packets must reply with the same id. This is needed to differentiate responses due to the stateless nature of UDP.
// QR	        Query Response	        1 bit	    0 for queries, 1 for responses.
// OPCODE	    Operation Code	        4 bits	    Typically always 0, see RFC1035 for details.
// AA	        Authoritative Answer	1 bit	    Set to 1 if the responding server is authoritative - that is, it "owns" - the domain queried.
// TC	        Truncated Message	    1 bit	    Set to 1 if the message length exceeds 512 bytes. Traditionally a hint that the query can be reissued using TCP, for which the length limitation doesn't apply.
// RD	        Recursion Desired	    1 bit	    Set by the sender of the request if the server should attempt to resolve the query recursively if it does not have an answer readily available.
// RA	        Recursion Available	    1 bit	    Set by the server to indicate whether or not recursive queries are allowed.
// Z	        Reserved	            3 bits	    Originally reserved for later use, but now used for DNSSEC queries.
// RCODE	    Response Code	        4 bits	    Set by the server to indicate the status of the response, i.e. whether or not it was successful or failed, and in the latter case providing details about the cause of the failure.
// QDCOUNT	    Question Count	        16 bits	    The number of entries in the Question Section
// ANCOUNT	    Answer Count	        16 bits	    The number of entries in the Answer Section
// NSCOUNT	    Authority Count	        16 bits	    The number of entries in the Authority Section
// ARCOUNT	    Additional Count	    16 bits	    The number of entries in the Additional Section

#[derive(Debug, Clone)]
struct MessageHeader {
    id: u16,
    qr: QueryResponseIndicator,
    op: OpCode,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    z: u8,
    rcode: u8,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

impl MessageHeader {
    fn to_bytes(&self) -> [u8; 12] {
        let mut bytes = [0; 12];

        bytes[0] = (self.id >> 8) as u8;
        bytes[1] = self.id as u8;

        bytes[2] = match self.qr { // Query Response Indicator
            QueryResponseIndicator::Query => 0,
            QueryResponseIndicator::Response => 1,
        } << 7 // shift left 7 bits to get the first bit (MSB)
            | (self.op as u8) << 3
            | (self.aa as u8) << 2
            | (self.tc as u8) << 1
            | (self.rd as u8);

        bytes[3] = (self.ra as u8) << 7 | self.z << 4 | self.rcode;

        bytes[4] = (self.qdcount >> 8) as u8;
        bytes[5] = self.qdcount as u8;

        bytes[6] = (self.ancount >> 8) as u8;
        bytes[7] = self.ancount as u8;

        bytes[8] = (self.nscount >> 8) as u8;
        bytes[9] = self.nscount as u8;

        bytes[10] = (self.arcount >> 8) as u8;
        bytes[11] = self.arcount as u8;

        bytes
    }
}

#[derive(Debug, Clone)]
struct Message {
    header: MessageHeader,
}

#[derive(Debug, Clone, Copy)]
enum QueryResponseIndicator {
    Query,
    Response,
}

#[derive(Debug, Clone, Copy)]
enum OpCode {
    Query, 
    InverseQuery,
    Status,
}

fn main() -> anyhow::Result<()> {
    let addr = "127.0.0.1:2053";
    eprintln!("Listening on {}", addr);

    let udp_socket = UdpSocket::bind(addr).expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        let (size, source) = udp_socket // size of the recieved data and the source of the data
            .recv_from(&mut buf) // recieve data from udp socket
            .context("recieve from udp socket")?;
        handle_packet(&buf[..size], source, &udp_socket).context("handle packet")?;
    }
}


fn handle_packet(packet: &[u8], source: SocketAddr, socket: &UdpSocket) -> anyhow::Result<()> {
    eprintln!("Received {} bytes from {}", packet.len(), source);

    let response = Message {
        header: MessageHeader {
            id: 1234, 
            qr: QueryResponseIndicator::Response,
            op: OpCode::Query,
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            z: 0,
            rcode: 0,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        },
    };

    let response = response.header.to_bytes();
    socket
        .send_to(&response, source) // sending data over a UDP socket to the source
        .expect("Failed to send response");

    Ok(())
}
