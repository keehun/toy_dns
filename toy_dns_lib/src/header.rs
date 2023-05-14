use crate::errors::DnsError;
use byteorder::{BigEndian, ReadBytesExt};
use std::io::Cursor;

/// A DNS header. See RFC 1035 for specifications on headers of DNS messages.
#[derive(Debug, PartialEq)]
pub struct Header {
    /// ID of the DNS message.
    pub id: u16,

    /// Flags for the DNS message.
    pub flags: u16,

    /// The number of questions in the DNS message.
    pub num_questions: u16,

    /// The number of answers in the DNS message.
    pub num_answers: u16,

    /// The number of authorities in the DNS message.
    pub num_authorities: u16,

    /// The number of additional records in the DNS message.
    pub num_additionals: u16,
}

impl Default for Header {
    fn default() -> Self {
        Header {
            id: 0,
            flags: 0,
            num_questions: 0,
            num_answers: 0,
            num_authorities: 0,
            num_additionals: 0,
        }
    }
}

impl Header {
    /// Read a DNS message header at the given cursor. Cursor will advance (even if the function
    /// fails) up to the last successful byte read.
    ///
    /// # Arguments
    /// * `cursor`: A cursor pointing at the byte buffer to attempt parsing from
    pub fn read_and_advance(cursor: &mut Cursor<&[u8]>) -> Result<Header, DnsError> {
        let Ok(id) = cursor.read_u16::<BigEndian>() else { return Err(DnsError::ParseId) };
        let Ok(flags) = cursor.read_u16::<BigEndian>() else { return Err(DnsError::ParseFlag) };
        let Ok(num_questions) = cursor.read_u16::<BigEndian>() else { return Err(DnsError::ParseQuestionCount) };
        let Ok(num_answers) = cursor.read_u16::<BigEndian>() else { return Err(DnsError::ParseAnswerCount) };
        let Ok(num_authorities) = cursor.read_u16::<BigEndian>() else { return Err(DnsError::ParseAuthorityCount) };
        let Ok(num_additionals) = cursor.read_u16::<BigEndian>() else { return Err(DnsError::ParseAdditionalCount) };

        return Ok(Header {
            id: id,
            flags: flags,
            num_questions: num_questions,
            num_answers: num_answers,
            num_authorities: num_authorities,
            num_additionals: num_additionals,
        });
    }
}

/// Validate parsing of a zeroed buffer. This is technically a valid header although it doesn't
/// make much sense to us.
#[test]
fn test_parsing_zero_buffer() {
    let data = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut cursor = Cursor::new(data.as_slice());
    assert!(Header::read_and_advance(&mut cursor).is_ok())
}

/// Validate parsing of a basic header.
#[test]
fn test_parsing_basic_header() {
    let data = [204, 71, 129, 128, 0, 1, 0, 1, 0, 0, 0, 0];
    let mut cursor = Cursor::new(data.as_slice());
    assert!(Header::read_and_advance(&mut cursor).is_ok())
}

/// Validate parsing of an incomplete header results in failure.
#[test]
fn test_parsing_incomplete_header() {
    // This data is one byte too short for a valid header
    let data = [204, 71, 129, 128, 0, 1, 0, 1, 0, 0, 0];
    let mut cursor = Cursor::new(data.as_slice());
    assert!(Header::read_and_advance(&mut cursor).is_err())
}

/// Validate parsing of an empty buffer results in failure.
#[test]
fn test_parsing_empty_buffer_header() {
    // This data is one byte too short for a valid header
    let data = [];
    let mut cursor = Cursor::new(data.as_slice());
    assert!(Header::read_and_advance(&mut cursor).is_err())
}
