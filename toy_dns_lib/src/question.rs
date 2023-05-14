use crate::errors::DnsError;
use crate::record::RecordType;
use crate::record_name::RecordName;
use byteorder::{BigEndian, ReadBytesExt};
use std::io::Cursor;

#[derive(Debug, PartialEq)]
pub struct Question {
    /// The domain name of interest in the question.
    pub name: Vec<u8>,

    /// Type of the DNS question.
    pub q_type: RecordType,

    /// Class of the DNS question.
    pub q_class: u16,
}

impl Question {
    /// Read a DNS question at the given cursor. Cursor will advance (even if the function fails) up to the last successful byte read.
    ///
    /// # Arguments
    /// * `cursor`: The byte buffer containing the full DNS message data.
    pub fn read_and_advance(cursor: &mut Cursor<&[u8]>) -> Result<Question, DnsError> {
        let name = RecordName::read_and_advance(cursor)?;
        let Ok(parsed_type) = cursor.read_u16::<BigEndian>() else { return Err(DnsError::ReadQuestionType) };
        let Some(record_type) = RecordType::from(parsed_type) else { return Err(DnsError::UnrecognizedRecordType) };
        let Ok(parsed_class) = cursor.read_u16::<BigEndian>() else { return Err(DnsError::ReadQuestionClass) };
        return Ok(Question {
            name: name,
            q_type: record_type,
            q_class: parsed_class,
        });
    }
}

/// Validate parsing of a valid question
#[test]
fn test_parsing_valid_question() {
    let data = [
        // www.example.com                                                           Type  Class
        3u8, 119, 119, 119, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1,
    ];

    let domain_name: Vec<u8> = "www.example.com".chars().map(|c| c as u8).collect();
    let expected = Question {
        name: domain_name,
        q_type: RecordType::A,
        q_class: 1,
    };

    let mut cursor = Cursor::new(data.as_slice());
    assert_eq!(Question::read_and_advance(&mut cursor).unwrap(), expected);
}

/// Validate parsing of a valid question
#[test]
fn test_parsing_valid_question_invalid_record_type() {
    let data = [
        // www.example.com                                                           Type  Class
        3u8, 119, 119, 119, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 44, 0, 1,
    ];

    let mut cursor = Cursor::new(data.as_slice());
    assert!(Question::read_and_advance(&mut cursor).is_err());
}

/// Validate proper handling of a buffer too small to hold a question.
#[test]
fn test_parsing_incomplete_question() {
    // Type and class are missing.
    let data = [
        3u8, 119, 119, 119, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0,
    ];
    let mut cursor = Cursor::new(data.as_slice());
    assert!(Question::read_and_advance(&mut cursor).is_err());
}
