use crate::errors::DnsError;
use crate::record_name::RecordName;
use byteorder::{BigEndian, ReadBytesExt};
use std::fmt;
use std::io::{Cursor, Read};

/// Types of DNS records supported by toy_dns.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum RecordType {
    Invalid,
    A,
    NS,
    AAAA,
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            RecordType::Invalid => "INVALID",
            RecordType::A => "A",
            RecordType::NS => "NS",
            RecordType::AAAA => "AAAA",
        };
        write!(f, "{}", name)
    }
}

impl RecordType {
    /// The integer value of each record type. Record types with value <= 16 are defined in
    /// RFC 1035. The AAAA record is specified in RFC 3596.
    pub fn value(record_type: RecordType) -> u16 {
        match record_type {
            RecordType::Invalid => 0,
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::AAAA => 28,
        }
    }

    pub fn from(record_type_value: u16) -> Option<RecordType> {
        match record_type_value {
            0 => Some(RecordType::Invalid),
            1 => Some(RecordType::A),
            2 => Some(RecordType::NS),
            28 => Some(RecordType::AAAA),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Record {
    /// Name of the DNS Record.
    pub name: Vec<u8>,

    /// Type of the DNS Record.
    pub r_type: RecordType,

    /// Class of the DNS Record.
    pub r_class: u16,

    /// TTL for the DNS record.
    pub ttl: u32,

    /// Data for the DNS record.
    pub data: Vec<u8>,
}

impl Default for Record {
    fn default() -> Self {
        Self {
            name: vec![],
            r_type: RecordType::Invalid,
            r_class: 0,
            ttl: 0,
            data: vec![],
        }
    }
}

impl Record {
    /// The IP address of the record as a string.
    pub fn ip_address(&self) -> String {
        let mut address = String::new();
        let mut data_iterator = self.data.iter().peekable();
        while let Some(datum) = data_iterator.next() {
            address.push_str(&format!("{}", datum));
            if data_iterator.peek().is_some() {
                address.push_str(".");
            }
        }
        return address;
    }

    /// Read a DNS record at the given cursor. Cursor will advance (even if the function fails) up to the last
    /// successful byte read.
    ///
    /// # Arguments
    /// * `cursor`: The byte buffer containing the full DNS message data.
    pub fn read_and_advance(cursor: &mut Cursor<&[u8]>) -> Result<Record, DnsError> {
        let record_name = RecordName::read_and_advance(cursor)?;
        let Ok(parsed_type) = cursor.read_u16::<BigEndian>() else { return Err(DnsError::ReadRecordType) };
        let Some(record_type) = RecordType::from(parsed_type) else { return Err(DnsError::UnrecognizedRecordType) };
        let Ok(parsed_class) = cursor.read_u16::<BigEndian>() else { return Err(DnsError::ReadRecordClass) };
        let Ok(parsed_ttl) = cursor.read_u32::<BigEndian>() else { return Err(DnsError::ReadRecordTTL) };
        let Ok(parsed_data_length) = cursor.read_u16::<BigEndian>() else { return Err(DnsError::ReadRecordDataLength) };

        let mut data = vec![0u8; parsed_data_length as usize];
        let Ok(_) = cursor.read_exact(&mut data) else { return Err(DnsError::ReadRecordData) };

        Ok(Record {
            name: record_name,
            r_type: record_type,
            r_class: parsed_class,
            ttl: parsed_ttl,
            data: data,
        })
    }
}

pub trait DnsRecordGetters {
    /// Get the first A record from the array of DNS records.
    fn get_first_a_record(&self) -> Option<&Record>;

    /// Get the first NS record from the array of DNS records.
    fn get_first_ns_record(&self) -> Option<&Record>;
}

impl DnsRecordGetters for [Record] {
    /// Retrieve the first A record from an array of records.
    fn get_first_a_record(&self) -> Option<&Record> {
        self.iter()
            .filter(|record| record.r_type == RecordType::A)
            .next()
    }

    /// Retrieve the first NS record from an array of records.
    fn get_first_ns_record(&self) -> Option<&Record> {
        self.iter()
            .filter(|record| record.r_type == RecordType::NS)
            .next()
    }
}

/// Validate serialization of an IP address from a record
#[test]
fn test_query_serialization() {
    // For the purposes of this test, none of the other fields in Record matter
    let record = Record {
        data: vec![93, 184, 216, 34],
        ..Default::default()
    };

    assert_eq!(record.ip_address(), "93.184.216.34");
}

#[test]
fn test_parsing_valid_record() {
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

    let mut cursor = Cursor::new(data.as_slice());
    cursor.set_position(33);

    let result = Record::read_and_advance(&mut cursor);

    assert_eq!(
        result.unwrap_or_default(),
        Record {
            name: "www.example.com".chars().map(|c| c as u8).collect(),
            r_type: RecordType::A,
            r_class: 1,
            ttl: 29 << 8 | 234,
            data: vec![93, 184, 216, 34]
        }
    )
}

/// Validate record parsing can handle a buffer too small to hold a record.
#[test]
fn test_parsing_incomplete_record_buffer() {
    // This buffer is too small to ever contain a valid record
    let data = [0, 0, 0, 0, 0, 0, 0, 0];
    let mut cursor = Cursor::new(data.as_slice());
    let result = Record::read_and_advance(&mut cursor);
    assert!(result.is_err())
}

/// Validate proper handling of records which claim to have more bytes in its data section than it
/// actually does.
#[test]
fn test_parsing_incomplete_record_data() {
    // Notice that the "Len" at the end says 6 but there are only 4 bytes under "Data". This should
    // result in an error.
    let data = [
        // Header                                  Question
        // ID    Flags     Qs    Answ  Auth  Addl     www               example
        204, 71, 129, 128, 0, 1, 0, 1, 0, 0, 0, 0, 3, 119, 119, 119, 7, 101, 120, 97, 109, 112,
        //                                        Answer
        //           com              Type  Class Ptr      Type  Class TTL            Len   Data
        108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 192, 12, 0, 1, 0, 1, 0, 0, 29, 234, 0, 6, 93, 184,
        216, 34,
    ];
    let mut cursor = Cursor::new(data.as_slice());
    cursor.set_position(33);

    let result = Record::read_and_advance(&mut cursor);
    assert_eq!(result, Err(DnsError::ReadRecordData));
}

/// Validate that get_first_a_record() returns the correct record when it's the first in the array.
#[test]
fn test_get_first_a_record_when_first_of_many() {
    let record_1 = Record {
        r_type: RecordType::A,
        r_class: 1,
        ..Default::default()
    };

    let record_2 = Record {
        r_type: RecordType::NS,
        r_class: 2,
        ..Default::default()
    };

    let record_3 = Record {
        r_type: RecordType::NS,
        r_class: 3,
        ..Default::default()
    };

    let records = vec![record_1.clone(), record_2, record_3];
    assert_eq!(records.get_first_a_record(), Some(&record_1));
}

/// Validate that get_first_a_record() returns the correct record when it's in the middle of an
/// array.
#[test]
fn test_get_first_a_record_when_middle_of_many() {
    let record_1 = Record {
        r_type: RecordType::A,
        r_class: 1,
        ..Default::default()
    };

    let record_2 = Record {
        r_type: RecordType::NS,
        r_class: 2,
        ..Default::default()
    };

    let record_3 = Record {
        r_type: RecordType::NS,
        r_class: 3,
        ..Default::default()
    };

    let records = vec![record_2, record_1.clone(), record_3];
    assert_eq!(records.get_first_a_record(), Some(&record_1));
}

/// Validate that get_first_a_record() returns the correct record when it's the last in the array.
#[test]
fn test_get_first_a_record_when_last_of_many() {
    let record_1 = Record {
        r_type: RecordType::A,
        r_class: 1,
        ..Default::default()
    };

    let record_2 = Record {
        r_type: RecordType::NS,
        r_class: 2,
        ..Default::default()
    };

    let record_3 = Record {
        r_type: RecordType::NS,
        r_class: 3,
        ..Default::default()
    };

    let records = vec![record_2, record_3, record_1.clone()];
    assert_eq!(records.get_first_a_record(), Some(&record_1));
}

/// Validate that get_first_ns_record() returns the correct record when it's the first in the array.
#[test]
fn test_get_first_ns_record_when_first_of_many() {
    let record_1 = Record {
        r_type: RecordType::NS,
        r_class: 1,
        ..Default::default()
    };

    let record_2 = Record {
        r_type: RecordType::A,
        r_class: 2,
        ..Default::default()
    };

    let record_3 = Record {
        r_type: RecordType::A,
        r_class: 3,
        ..Default::default()
    };

    let records = vec![record_1.clone(), record_2, record_3];
    assert_eq!(records.get_first_ns_record(), Some(&record_1));
}

/// Validate that get_first_ns_record() returns the correct record when it's in the middle of an
/// array.
#[test]
fn test_get_first_ns_record_when_middle_of_many() {
    let record_1 = Record {
        r_type: RecordType::NS,
        r_class: 1,
        ..Default::default()
    };

    let record_2 = Record {
        r_type: RecordType::A,
        r_class: 2,
        ..Default::default()
    };

    let record_3 = Record {
        r_type: RecordType::A,
        r_class: 3,
        ..Default::default()
    };

    let records = vec![record_2, record_1.clone(), record_3];
    assert_eq!(records.get_first_ns_record(), Some(&record_1));
}

/// Validate that get_first_ns_record() returns the correct record when it's the last in the array.
#[test]
fn test_get_first_ns_record_when_last_of_many() {
    let record_1 = Record {
        r_type: RecordType::NS,
        r_class: 1,
        ..Default::default()
    };

    let record_2 = Record {
        r_type: RecordType::A,
        r_class: 2,
        ..Default::default()
    };

    let record_3 = Record {
        r_type: RecordType::A,
        r_class: 3,
        ..Default::default()
    };

    let records = vec![record_2, record_3, record_1.clone()];
    assert_eq!(records.get_first_ns_record(), Some(&record_1));
}
