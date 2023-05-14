use crate::errors::DnsError;
use crate::header::Header;
use crate::question::Question;
use crate::record::Record;
use std::fmt;
use std::io::Cursor;

pub struct Packet {
    /// Header of a DNS packet.
    pub header: Header,

    /// Questions in a DNS packet.
    pub questions: Vec<Question>,

    /// Answers in a DNS packet.
    pub answers: Vec<Record>,

    /// Authorities in a DNS packet.
    pub authorities: Vec<Record>,

    /// Additional records in a DNS packet.
    pub additionals: Vec<Record>,
}

impl fmt::Display for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (position, answer) in self.answers.iter().enumerate() {
            let Ok(name) = std::str::from_utf8(&answer.name) else {return Err(fmt::Error)};
            let address = answer.ip_address();
            write!(
                f,
                "{}{}#{}@{}/{}",
                if position == 0 { "" } else { "," },
                answer.r_type,
                name,
                address,
                answer.ttl
            )?;
        }
        Ok(())
    }
}

impl Packet {
    /// Parse a DNS packet from the given buffer.
    ///
    /// # Arguments
    /// * `buffer`: The byte buffer containing the full DNS message data.
    pub fn parse(buffer: &[u8]) -> Result<Packet, DnsError> {
        let mut cursor = Cursor::new(buffer);
        let header = Header::read_and_advance(&mut cursor)?;
        let mut questions = Vec::with_capacity(header.num_questions as usize);

        for _ in 0..header.num_questions {
            let question = Question::read_and_advance(&mut cursor)?;
            questions.push(question);
        }

        let mut answers = Vec::with_capacity(header.num_answers as usize);
        for _ in 0..header.num_answers {
            let answer = Record::read_and_advance(&mut cursor)?;
            answers.push(answer);
        }

        let mut authorities = Vec::with_capacity(header.num_authorities as usize);
        for _ in 0..header.num_authorities {
            let authority = Record::read_and_advance(&mut cursor)?;
            authorities.push(authority);
        }

        let mut additionals = Vec::with_capacity(header.num_additionals as usize);
        for _ in 0..header.num_additionals {
            let record = Record::read_and_advance(&mut cursor)?;
            additionals.push(record);
        }

        Ok(Packet {
            header: header,
            questions: questions,
            answers: answers,
            authorities: authorities,
            additionals: additionals,
        })
    }
}

/// Validate parsing of a simple, valid packet.
#[test]
fn test_parsing_simple_packet() {
    use crate::record::RecordType;

    // A DNS packet that answers a query for www.example.com
    let data = [
        // Header                                  Question
        // ID    Flags     Qs    Answ  Auth  Addl     www               example
        204, 71, 129, 128, 0, 1, 0, 1, 0, 0, 0, 0, 3, 119, 119, 119, 7, 101, 120, 97, 109, 112,
        //                                        Answer
        //           com              Type  Class Ptr      Type  Class TTL            Len   Data
        108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 192, 12, 0, 1, 0, 1, 0, 0, 29, 234, 0, 4, 93, 184,
        216, 34,
    ];

    let result = Packet::parse(data.as_slice());
    assert!(result.is_ok());
    let packet = result.unwrap();

    assert_eq!(
        packet.header,
        Header {
            id: 204 << 8 | 71,
            flags: 129 << 8 | 128,
            num_questions: 1,
            num_answers: 1,
            num_authorities: 0,
            num_additionals: 0,
        }
    );

    let domain_name: Vec<u8> = "www.example.com".chars().map(|c| c as u8).collect();

    assert_eq!(
        packet.questions,
        vec![Question {
            name: domain_name.clone(),
            q_type: RecordType::A,
            q_class: 1,
        }]
    );

    assert_eq!(
        packet.answers,
        vec![Record {
            name: domain_name,
            r_type: RecordType::A,
            r_class: 1,
            ttl: 29 << 8 | 234,
            data: vec![93, 184, 216, 34]
        }]
    )
}

/// Validate parsing of a packet with only a header.
#[test]
fn test_parsing_packet_with_header() {
    // This data contains only the header portion from a real packet. Because the header says there
    // is 1 question and 1 anwser while there is no actual data, parsing should fail.
    //                    ID       Flags     Qs    Answ  Auth  Addl
    let data = [204, 71, 129, 128, 0, 0, 0, 0, 0, 0, 0, 0];
    assert!(Packet::parse(data.as_slice()).is_ok())
}

/// Validate parsing a packet with a header which expects questions and answers which are missing.
#[test]
fn test_parsing_packet_with_header_and_missing_data_should_fail() {
    // The header says there is 1 question and 1 anwser but both are missing.
    //                    ID       Flags     Qs    Answ  Auth  Addl
    let data = [204, 71, 129, 128, 0, 1, 0, 1, 0, 0, 0, 0];
    assert!(Packet::parse(data.as_slice()).is_err())
}

/// Validate parsing of a packet with missing data fails.
#[test]
fn test_parsing_packet_with_missing_data_should_fail() {
    // The header says there is 1 question and 1 anwser but the answer is missing.
    let data = [
        //ID     Flags     Qs    Answ  Auth  Addl  www               example
        204, 71, 129, 128, 0, 1, 0, 1, 0, 0, 0, 0, 3, 119, 119, 119, 7, 101, 120, 97, 109, 112, 108,
        //   com
        101, 3, 99, 111, 109, 0,
    ];
    assert!(Packet::parse(data.as_slice()).is_err())
}

/// Validate parsing of a packet with 0 bytes fails.
#[test]
fn test_parsing_packet_with_no_data_should_fail() {
    assert!(Packet::parse([].as_slice()).is_err())
}
