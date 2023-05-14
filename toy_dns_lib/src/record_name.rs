use crate::errors::DnsError;
use byteorder::ReadBytesExt;
use log::debug;
use std::io::{Cursor, Seek, SeekFrom};

/// Establish an underlying type for a name that has been encoded
type EncodedName = Vec<u8>;

/// Name within a DNS message
pub struct RecordName<'a> {
    pub name: &'a str,
}

/// When the upper two bits are set on a length byte, it signifies that the name part is a
/// compression pointer.
const COMPRESSION_SIGNIFIER: u8 = 0b1100_0000;

impl<'a> RecordName<'a> {
    /// Encode the name into a format appropriate for queries over the wire.
    pub fn encode(&'a self) -> Result<EncodedName, DnsError> {
        if !self.name.chars().all(|c| c.is_ascii()) {
            return Err(DnsError::InvalidByteInName);
        }

        let name_parts = self.name.split(".");
        let mut name_bytes = EncodedName::new();
        for part in name_parts {
            let mut part_as_bytes = vec![part.len() as u8];
            part_as_bytes.extend(part.chars().into_iter().map(|c| c as u8));
            name_bytes.extend(part_as_bytes)
        }

        // The name needs to be null-terminated which will not be done automatically
        name_bytes.push(0x0);
        return Ok(name_bytes);
    }

    /// Read a DNS record name at the given cursor. Cursor will advance (even if the function fails)
    /// up to the last successful byte read.
    ///
    /// # Arguments
    /// * `cursor`: The byte buffer containing the full DNS message data.
    pub fn read_and_advance(cursor: &mut Cursor<&[u8]>) -> Result<Vec<u8>, DnsError> {
        let mut parts: Vec<String> = Vec::new();

        // Loop as long as we continue to see valid bytes
        loop {
            match cursor.read_u8() {
                // If we encounter a null terminator, then we're done
                Ok(0) => break,

                // If we get a value, then this indicates length of the name-part.
                // Processing within this scope advances the cursor so that next time this loops,
                // the cursor should be at another length byte (if any).
                Ok(length) => {
                    // Section 4.1.4 of RFC 1035 specifies a compression scheme used to reduce
                    // the data transmitted for verbose DNS messages. In this scheme, a "pointer"
                    // is indicated by setting the first two bytes with 1s.
                    if length & COMPRESSION_SIGNIFIER > 0 {
                        // In this case, we need decompression.

                        // Because length has the first two bits set, length cannot be taken
                        // "literally" as a value. Before the actual length can be read from the
                        // variable, we need to unset the first two bits.
                        let length_without_compression_signifiers = length & !COMPRESSION_SIGNIFIER;
                        let Ok(part_string) = std::string::String::from_utf8(
                            Self::read_and_advance_compressed_bytes(
                                length_without_compression_signifiers,
                                cursor,
                            )?,
                        ) else {
                            return Err(DnsError::InvalidByteInName)
                        };
                        parts.push(part_string);
                        break;
                    } else {
                        let mut part_bytes = Vec::new();
                        // In this case, we don't need to handle decompression.
                        // Pick the number of bytes indicated by length. This advances the cursor.
                        for _ in 0..length {
                            match cursor.read_u8() {
                                Ok(byte) => {
                                    part_bytes.push(byte);
                                }
                                Err(_) => {
                                    return Err(DnsError::ReadByte);
                                }
                            }
                        }

                        let Ok(part_string) = std::string::String::from_utf8(part_bytes) else {
                            return Err(DnsError::InvalidByteInName)
                         };
                        parts.push(part_string);
                    }
                }

                Err(_) => return Err(DnsError::ReadLength),
            }
        }

        let bytes = parts.join(".");
        return Ok(bytes.into_bytes());
    }

    /// Read a compressed name byte sequence at the given cursor. This function assumes that the
    /// cursor is at the position immediately following the length byte.
    ///
    /// # Arguments
    /// * `length`: The first byte of a name part. The function assumes that the first two bits have
    ///             been zeroed even though it would have been set to 1 which signified that it is a
    ///             compression pointer.
    /// * `cursor`: The byte buffer containing the full DNS message data.
    fn read_and_advance_compressed_bytes(
        length: u8,
        cursor: &mut Cursor<&[u8]>,
    ) -> Result<EncodedName, DnsError> {
        let Ok(next_byte) = cursor.read_u8() else { return Err(DnsError::DecompressReadByte) };
        let shifted_length = (length as u16) << 8;
        let offset = (shifted_length | next_byte as u16) as u64;

        let previous_position = cursor.position();
        debug!("Saved previous position: {}", previous_position);
        debug!("Seeking from beginning: {}", offset);
        let Ok(_) = cursor.seek(SeekFrom::Start(offset)) else { return Err(DnsError::DecompressSkip); };
        let result = RecordName::read_and_advance(cursor)?;
        debug!("Restoring position of {}", previous_position);
        let Ok(_) = cursor.seek(SeekFrom::Start(previous_position)) else { return Err(DnsError::DecompressRestore); };
        Ok(result)
    }
}

/// Validate decoding of an uncompressed DNS name.
#[test]
fn test_decode_uncompressed_name() -> Result<(), DnsError> {
    // Bytes that represent www.example.com
    let expected_name = "www.example.com";

    // This byte buffer reflects the part of a DNS message that contains an uncompressed name.
    // Each host name part is proceeded by a length marker. Multiple 0s are appended at the end
    // so that we can validate that those bytes remain "unread".
    let message_bytes = [
        3, 119, 119, 119, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 0, 0, 0, 0,
    ];

    let mut cursor = Cursor::new(message_bytes.as_slice());

    assert_eq!(
        RecordName::read_and_advance(&mut cursor)?,
        expected_name.as_bytes()
    );
    assert_eq!(cursor.position(), 17);
    Ok(())
}

/// Validate decoding of an uncompressed DNS name which is missing data
#[test]
fn test_decode_uncompressed_name_with_missing_data() {
    let message_bytes = [3, 119];
    let mut cursor = Cursor::new(message_bytes.as_slice());
    assert!(RecordName::read_and_advance(&mut cursor).is_err())
}

/// Validate decoding of an uncompressed DNS name which is missing data
#[test]
fn test_decode_uncompressed_name_with_invalid_utf8() {
    let message_bytes = [1, 0x80];
    let mut cursor = Cursor::new(message_bytes.as_slice());
    assert!(RecordName::read_and_advance(&mut cursor).is_err())
}

// This example buffer comes from RFC 1035, section 4.1.4:
//
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     20 |           1           |           F           |
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     22 |           3           |           I           |
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     24 |           S           |           I           |
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     26 |           4           |           A           |
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     28 |           R           |           P           |
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     30 |           A           |           0           |
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     40 |           3           |           F           |
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     42 |           O           |           O           |
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     44 | 1  1|                20                       |
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     64 | 1  1|                26                       |
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     92 |           0           |                       |
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// The last row has been omitted.
#[rustfmt::skip]
#[cfg(test)]
const RFC_1035_4_1_4_EXAMPLE: [u8; 67] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Padding
    1, b'F', 3, b'I', b'S', b'I', 4, b'A', b'R', b'P', b'A', 0, // 20 - 31
    0, 0, 0, 0, 0, 0, 0, 0, 3,                                  // Padding
    b'F', b'O', b'O', 0b1100_0000, 20,                          // 40 - 45
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,       // Padding
    0b1100_0000, 26, 0,                                         // 64 - 65
];

/// Validate decoding of a record name which only contains a pointer.
#[test]
fn test_decode_compressed_name_only_pointer() -> Result<(), DnsError> {
    let expected_name = "F.ISI.ARPA";
    let mut cursor = Cursor::new(RFC_1035_4_1_4_EXAMPLE.as_slice());
    cursor.set_position(20);

    assert_eq!(
        RecordName::read_and_advance(&mut cursor)?,
        expected_name.as_bytes()
    );
    Ok(())
}

/// Validate decoding of a record name which contains a pointer to middle of a previous name.
#[test]
fn test_decode_compressed_name_partial_pointer() -> Result<(), DnsError> {
    let expected_name = "ARPA";
    let mut cursor = Cursor::new(RFC_1035_4_1_4_EXAMPLE.as_slice());
    cursor.set_position(64);

    assert_eq!(
        RecordName::read_and_advance(&mut cursor)?,
        expected_name.as_bytes()
    );
    Ok(())
}

#[test]
/// Validate decoding of a record name which begins with a normal part but ends with a pointer.
fn test_decode_compressed_name_after_normal_part() -> Result<(), DnsError> {
    let expected_name = "FOO.F.ISI.ARPA";
    let mut cursor = Cursor::new(RFC_1035_4_1_4_EXAMPLE.as_slice());
    cursor.set_position(40);

    assert_eq!(
        RecordName::read_and_advance(&mut cursor)?,
        expected_name.as_bytes()
    );
    Ok(())
}

#[test]
/// Validate encoding of a record name
fn test_encoding_record_name() -> Result<(), DnsError> {
    let name_to_encode = RecordName {
        name: "toy.dns.project",
    };

    assert_eq!(
        name_to_encode.encode()?,
        [
            3, b't', b'o', b'y', 3, b'd', b'n', b's', 7, b'p', b'r', b'o', b'j', b'e', b'c', b't',
            0
        ]
    );

    Ok(())
}

#[test]
/// Validate encoding of an invalid record name
fn test_encoding_invalid_record_name() {
    let invalid_name = RecordName { name: "👍" };
    assert!(invalid_name.encode().is_err());
}
