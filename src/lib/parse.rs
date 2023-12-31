pub fn parse_message(input: &[u8]) -> anyhow::Result<Message> {
    let (input, header) = parse_header(&input).unwrap();
    Ok(Message { header })
}
pub type BitInput<'a> = (&'a [u8], usize);

pub fn parse_header_from_bits(input: BitInput) -> IResult<(&[u8], usize), MessageHeader> {
    let (input, id) = nom::bits::complete::take(16usize)(input)?;
    let (input, qr) = nom::bits::complete::take(1usize)(input)?;
    let (input, op) = nom::bits::complete::take(4usize)(input)?;
    let (input, aa): ((&[u8], usize), u8) = nom::bits::complete::take(1usize)(input)?;
    let (input, tc): ((&[u8], usize), u8) = nom::bits::complete::take(1usize)(input)?;
    let (input, rd): ((&[u8], usize), u8) = nom::bits::complete::take(1usize)(input)?;
    let (input, ra): ((&[u8], usize), u8) = nom::bits::complete::take(1usize)(input)?;
    let (input, z) = nom::bits::complete::take(3usize)(input)?;
    let (input, rcode) = nom::bits::complete::take(4usize)(input)?;
    let (input, qdcount) = nom::bits::complete::take(16usize)(input)?;
    let (input, ancount) = nom::bits::complete::take(16usize)(input)?;
    let (input, nscount) = nom::bits::complete::take(16usize)(input)?;
    let (input, arcount) = nom::bits::complete::take(16usize)(input)?;
    let header = MessageHeader {
        id,
        qr: match qr {
            0 => QueryResponseIndicator::Query,
            1 => QueryResponseIndicator::Response,
            _ => unreachable!(),
        },
        op: match op {
            0 => OpCode::Query,
            1 => OpCode::InverseQuery,
            2 => OpCode::Status,
            _ => unreachable!(),
        },
        aa: aa == 1,
        tc: tc == 1,
        rd: rd == 1,
        ra: ra == 1,
        z,
        rcode,
        qdcount,
        ancount,
        nscount,
        arcount,
    };
    Ok((input, header))

}

pub fn parse_header(input: &[u8]) -> IResult<&[u8], MessageHeader> {
    let ((input, _), header) = parse_header_from_bits((input, 0)).unwrap();
    Ok((input, header))
}