use bytes::{BufMut, BytesMut};

#[derive(Debug, Clone)]
pub struct LabelSequence(String);

impl LabelSequence {
    pub fn new(s: &str) -> Self {
        Self(s.to_string())
    }

    pub fn to_bytes(&self, bytes: &mut BytesMut) {
        for label in self.0.split('.') {
            bytes.put_u8(label.len() as u8);
            bytes.put_slice(label.as_bytes());
        }
        bytes.put_u8(0);
    }
}

#[derive(Debug, Clone, Copy)]
pub enum QuestionType {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
}

#[derive(Debug, Clone, Copy)]
pub enum QuestionClass {
    IN = 1,
    CH = 3,
    HS = 4,
}

#[derive(Debug, Clone)]
pub struct Question {
    qname: LabelSequence,
    qtype: QuestionType,
    qclass: QuestionClass,
}

impl Question {
    pub fn new(qname: &str, qtype: QuestionType, qclass: QuestionClass) -> Self {
        Self {
            qname: LabelSequence::new(qname),
            qtype,
            qclass,
        }
    }

    pub fn to_bytes(&self, bytes: &mut BytesMut) {
        self.qname.to_bytes(bytes);
        bytes.put_u16(self.qtype as u16);
        bytes.put_u16(self.qclass as u16);
    }
}

// let mut bytes = BytesMut::with_capacity(512);
// let question = Question::new("google.com", QuestionType::A, QuestionClass::IN);
// let question_bytes = question.to_bytes(&mut bytes);







/* QTypes
    TYPE            value and meaning
    A               1 a host address
    NS              2 an authoritative name server
    MD              3 a mail destination (Obsolete - use MX)
    MF              4 a mail forwarder (Obsolete - use MX)
    CNAME           5 the canonical name for an alias
    SOA             6 marks the start of a zone of authority
    MB              7 a mailbox domain name (EXPERIMENTAL)
    MG              8 a mail group member (EXPERIMENTAL)
    MR              9 a mail rename domain name (EXPERIMENTAL)
    NULL            10 a null RR (EXPERIMENTAL)
    WKS             11 a well known service description
    PTR             12 a domain name pointer
    HINFO           13 host information
    MINFO           14 mailbox or mail list information
    MX              15 mail exchange
    TXT             16 text strings
*/

/* QClass
    CLASS           value and meaning
    IN              1 the Internet
    CS              2 the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CH              3 the CHAOS class
    HS              4 Hesiod [Dyer 87]
*/