/*
DNS Server Messages
    +---------------------+
    |        Header       |
    +---------------------+
    |       Question      | the question for the name server
    +---------------------+
    |        Answer       | RRs answering the question
    +---------------------+
    |      Authority      | RRs pointing toward an authority
    +---------------------+
    |      Additional     | RRs holding additional information
    +---------------------+
*/
#![allow(unused)]

use anyhow::Context;
use bytes::buf::Writer;
use bytes::{BufMut, BytesMut};
use nom::IResult;
use std::net::{SocketAddr, UdpSocket};

/* Header Structure
    RFC Name	    Descriptive Name	    Length	    Description
    ID	        Packet Identifier	    16 bits	    A random identifier is assigned to query packets. Response packets must reply with the same id. This is needed to differentiate responses due to the stateless nature of UDP.
    QR	        Query Response	        1 bit	    0 for queries, 1 for responses.
    OPCODE	    Operation Code	        4 bits	    Typically always 0, see RFC1035 for details.
    AA	        Authoritative Answer	1 bit	    Set to 1 if the responding server is authoritative - that is, it "owns" - the domain queried.
    TC	        Truncated Message	    1 bit	    Set to 1 if the message length exceeds 512 bytes. Traditionally a hint that the query can be reissued using TCP, for which the length limitation doesn't apply.
    RD	        Recursion Desired	    1 bit	    Set by the sender of the request if the server should attempt to resolve the query recursively if it does not have an answer readily available.
    RA	        Recursion Available	    1 bit	    Set by the server to indicate whether or not recursive queries are allowed.
    Z	        Reserved	            3 bits	    Originally reserved for later use, but now used for DNSSEC queries.
    RCODE	    Response Code	        4 bits	    Set by the server to indicate the status of the response, i.e. whether or not it was successful or failed, and in the latter case providing details about the cause of the failure.
    QDCOUNT	    Question Count	        16 bits	    The number of entries in the Question Section
    ANCOUNT	    Answer Count	        16 bits	    The number of entries in the Answer Section
    NSCOUNT	    Authority Count	        16 bits	    The number of entries in the Authority Section
    ARCOUNT	    Additional Count	    16 bits	    The number of entries in the Additional Section

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

/* Question Structure
    The question section is used to carry the "question" in most queries,
    i.e., the parameters that define what is being asked.  The section
    contains QDCOUNT (usually 1) entries.

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    <length><content>/<nullbyte>
    Eg: google.com is encoded as \x06google\x03com\x00
*/

mod sections;
use sections::header::*;
use sections::question::*;

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

    let mut response_bytes = BytesMut::with_capacity(512);

    let question = Question::new(
        "google.com", 
        QuestionType::A, 
        QuestionClass::IN    
    );

    let dns_message = Message {
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
        question: question.clone(),
    };
    dns_message.to_bytes(&mut response_bytes);
    

    socket
        .send_to(&response_bytes, source) // sending data over a UDP socket to the source
        .expect("Failed to send response");

    Ok(())
}
