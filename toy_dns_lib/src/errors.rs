use std::{error::Error, fmt};

#[derive(Debug, PartialEq)]
pub enum DnsError {
    // Parse Errors
    ParseResponse,
    ParseId,
    ParseFlag,
    ParseQuestionCount,
    ParseAnswerCount,
    ParseAuthorityCount,
    ParseAdditionalCount,
    ReadByte,
    ReadLength,
    ReadQuestionType,
    ReadQuestionClass,
    ReadRecordType,
    ReadRecordClass,
    ReadRecordTTL,
    ReadRecordDataLength,
    ReadRecordData,

    // Record Errors
    InvalidByteInName,
    UnrecognizedRecordType,

    // Socket Errors
    SocketBind,
    SocketSend,
    SocketRead,

    // Decompress Errors
    DecompressReadByte,
    DecompressSkip,
    DecompressRestore,

    // Serialization Errors
    QuerySerialization,

    // Additional Nameservers Not Found
    UnknownDomainName,
}

impl DnsError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::ParseResponse => 2,
            Self::ParseId => 3,
            Self::ParseFlag => 4,
            Self::ParseQuestionCount => 5,
            Self::ParseAnswerCount => 6,
            Self::ParseAuthorityCount => 7,
            Self::ParseAdditionalCount => 8,
            Self::ReadByte => 9,
            Self::ReadLength => 10,
            Self::ReadQuestionType => 11,
            Self::ReadQuestionClass => 12,
            Self::ReadRecordType => 13,
            Self::ReadRecordClass => 14,
            Self::ReadRecordTTL => 15,
            Self::ReadRecordDataLength => 16,
            Self::ReadRecordData => 17,
            Self::SocketBind => 18,
            Self::SocketSend => 19,
            Self::SocketRead => 20,
            Self::DecompressReadByte => 21,
            Self::DecompressSkip => 22,
            Self::DecompressRestore => 23,
            Self::QuerySerialization => 24,
            Self::UnrecognizedRecordType => 25,
            Self::InvalidByteInName => 26,
            Self::UnknownDomainName => 27,
        }
    }
}

impl Error for DnsError {}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let description = match self {
            Self::ParseResponse => "Could not parse DNS response",
            Self::ParseId => "Could not parse ID in header",
            Self::ParseFlag => "Could not parse flag in header",
            Self::ParseQuestionCount => "Could not parse number of questions",
            Self::ParseAnswerCount => "Could not parse number of answers",
            Self::ParseAuthorityCount => "Could not parse number of authorities",
            Self::ParseAdditionalCount => "Could not parse number of additionals",
            Self::ReadByte => "Could not read the next byte",
            Self::ReadLength => "Could not read length in string buffer",
            Self::ReadQuestionType => "Could not read type in question",
            Self::ReadQuestionClass => "Could not read class in question",
            Self::ReadRecordType => "Could not read type in record",
            Self::ReadRecordClass => "Could not read class in record",
            Self::ReadRecordTTL => "Could not read TTL in record",
            Self::ReadRecordDataLength => "Could not read length of data in record",
            Self::ReadRecordData => "Could not read data in record",
            Self::SocketBind => "Could not bind to socket",
            Self::SocketSend => "Could not send data through socket",
            Self::SocketRead => "Could not read data from socket",
            Self::DecompressReadByte => "Could not read additional byte to read skip offset",
            Self::DecompressSkip => "Skip failed, most likely was out of bounds",
            Self::DecompressRestore => "Could not restore cursor to previous position",
            Self::QuerySerialization => "Could not serialize DNS query",
            Self::UnrecognizedRecordType => "Did not recognize the record type value",
            Self::InvalidByteInName => "Found invalid byte in record name",
            Self::UnknownDomainName => "No nameservers are aware of the given domain name",
        };
        write!(f, "{:?}: {}", self, description)
    }
}
