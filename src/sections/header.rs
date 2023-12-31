use anyhow::Context;
use bytes::buf::Writer;
use bytes::{BufMut, BytesMut};
use nom::IResult;
use std::net::{SocketAddr, UdpSocket};

use crate::sections::question::{Question, QuestionClass, QuestionType};

#[derive(Debug, Clone)]
pub struct MessageHeader {
    pub id: u16,
    pub qr: QueryResponseIndicator,
    pub op: OpCode,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub z: u8,
    pub rcode: u8,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl MessageHeader {
    pub fn new(
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
    ) -> Self {
        Self {
            id,
            qr,
            op,
            aa,
            tc,
            rd,
            ra,
            z,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        }
    }

    pub fn to_bytes(&self) -> [u8; 12] {
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
pub struct Message {
    pub header: MessageHeader,
    pub question: Question,
}

impl Message {
    pub fn new(header: MessageHeader, question: Question) -> Self {
        Self { 
            header,
            question,
        }
    }

    pub fn to_bytes(&self, bytes: &mut BytesMut) {
        bytes.put_slice(&self.header.to_bytes());
        self.question.to_bytes(bytes);
    }
}

#[derive(Debug, Clone, Copy)]
pub enum QueryResponseIndicator {
    Query,
    Response,
}

#[derive(Debug, Clone, Copy)]
pub enum OpCode {
    Query, 
    InverseQuery,
    Status,
}