use crate::errors::DnsError;
use crate::header::Header;
use crate::packet::Packet;
use crate::question::Question;
use crate::record::{DnsRecordGetters, RecordType};
use crate::record_name::RecordName;
use crate::root_servers::{RootServer, RootServerName};
use crate::socket::Socket;
use byteorder::{BigEndian, WriteBytesExt};
use log::info;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::io::Cursor;
use std::mem::size_of;

// TODO: When toy_dns_lib supports more than CLASS_IN, this should become an enum.
const CLASS_IN: u16 = 1;

/// DNS Query
pub struct Query<'a> {
    /// Domain name for the query.
    pub domain_name: &'a str,

    /// Record type for the query.
    pub record_type: RecordType,
}

impl Query<'_> {
    /// Recursively resolves a DNS query for the given domain name and record type.
    ///
    /// # Argument
    /// * `socket`: The socket on which to perform the DNS query.
    /// * `rand_seed`: The seed for RNG, if desired.
    pub fn resolve<T>(
        &self,
        socket: &mut Box<dyn Socket<T>>,
        rand_seed: Option<usize>,
    ) -> Result<Packet, DnsError> {
        self.resolve_with_depth(socket, 0, rand_seed)
    }

    /// Serialize the query into bytes to send to a DNS server.
    ///
    /// # Argument
    /// * `rand_seed`: The seed for RNG, if desired.
    fn serialize(&self, rand_seed: Option<usize>) -> Result<Vec<u8>, DnsError> {
        let random_id = match rand_seed {
            None => rand::thread_rng().gen_range(0..=u16::MAX),
            Some(value) => ChaCha8Rng::seed_from_u64(value as u64).gen_range(0..=u16::MAX),
        };

        let header = Header {
            id: random_id,
            num_questions: 1,
            ..Default::default()
        };

        let question = Question {
            name: RecordName {
                name: self.domain_name,
            }
            .encode()?,
            q_type: self.record_type,
            q_class: CLASS_IN,
        };

        // Serialize the header & question
        let mut bytes: Vec<u8> =
            Vec::with_capacity(size_of::<Header>() + size_of::<Question>() + question.name.len());

        // Serialize the header
        let Ok(_) = bytes.write_u16::<BigEndian>(header.id) else { return Err(DnsError::QuerySerialization) };
        let Ok(_) = bytes.write_u16::<BigEndian>(header.flags) else { return Err(DnsError::QuerySerialization) };
        let Ok(_) = bytes.write_u16::<BigEndian>(header.num_questions) else { return Err(DnsError::QuerySerialization) };
        let Ok(_) = bytes.write_u16::<BigEndian>(header.num_answers) else { return Err(DnsError::QuerySerialization) };
        let Ok(_) = bytes.write_u16::<BigEndian>(header.num_authorities) else { return Err(DnsError::QuerySerialization) };
        let Ok(_) = bytes.write_u16::<BigEndian>(header.num_additionals) else { return Err(DnsError::QuerySerialization) };

        // Serialize the question
        bytes.extend(question.name);
        let Ok(_) = bytes.write_u16::<BigEndian>(RecordType::value(question.q_type)) else { return Err(DnsError::QuerySerialization) };
        let Ok(_) = bytes.write_u16::<BigEndian>(question.q_class) else { return Err(DnsError::QuerySerialization) };

        Ok(bytes)
    }

    /// Serializes then sends a DNS query over the wire to the given DNS server.
    ///
    /// # Arguments
    /// * `dns_server_ip`: The IP address of the DNS server to send the query to.
    /// * `dns_server_name`: The name of the DNS server if known. Only used for logging purposes.
    /// * `recursion_depth`: The current level of recursion. Only used for logging purposes.
    /// * `rand_seed`: The seed for RNG, if desired.
    fn perform<T>(
        &self,
        socket: &mut Box<dyn Socket<T>>,
        dns_server_ip: &str,
        dns_server_name: &str,
        recursion_depth: u16,
        rand_seed: Option<usize>,
    ) -> Result<Packet, DnsError> {
        info!(
            "{}Looking up {} at {} {}",
            " ".repeat((recursion_depth * 4).into()),
            self.domain_name,
            dns_server_ip,
            if dns_server_name != "" {
                format!("({})", dns_server_name)
            } else {
                "".to_owned()
            }
        );

        let Ok(query_bytes) = self.serialize(rand_seed) else {
            return Err(DnsError::QuerySerialization);
        };

        let Ok(_) = socket.send(&query_bytes, &format!("{}:53", dns_server_ip)) else {
            return Err(DnsError::SocketSend);
        };

        // 1024 is a good rule of thumb max-size for a DNS answer. For a more serious DNS resolver,
        // this mechanism should be improved.
        let mut buf = [0; 1024];
        match (*socket).recv_from(&mut buf) {
            Ok(_) => {
                info!(
                    "Queried \"{:?}\" {}:53 received: {:?}",
                    query_bytes, dns_server_ip, buf
                );
                return Packet::parse(&buf);
            }
            Err(_) => {
                return Err(DnsError::SocketRead);
            }
        };
    }

    /// Recursively resolves a DNS query for the given domain name and record type.
    ///
    /// # Arguments
    /// * `socket`: The socket to perform network calls on.
    /// * `recursion_depth`: The recursion depth. Used only for logging purposes.
    /// * `rand_seed`: The seed for RNG, if desired.
    fn resolve_with_depth<T>(
        &self,
        socket: &mut Box<dyn Socket<T>>,
        recursion_depth: u16,
        rand_seed: Option<usize>,
    ) -> Result<Packet, DnsError> {
        let root_server = RootServer::random(rand_seed);
        let mut name_server_ip: String = (*root_server.0).to_owned();
        let mut name_server_host: String;
        let RootServerName(name_server_str) = *root_server.1;
        name_server_host = name_server_str.to_owned();
        loop {
            match self.perform(
                socket,
                &name_server_ip,
                &name_server_host,
                recursion_depth,
                rand_seed,
            ) {
                Ok(packet) => {
                    if packet.answers.get_first_a_record().is_some() {
                        return Ok(packet);
                    } else if let Some(new_name_server) = packet.additionals.get_first_a_record() {
                        // There was no A record returned. The nameserver didn't have an A record
                        // for the domain. We'll have to try the next nameserver.
                        name_server_ip = new_name_server.ip_address();
                        name_server_host = "".to_owned();
                    } else if let Some(ns_record) = packet.authorities.get_first_ns_record() {
                        // At this point, the authority doesn't know which DNS server to point us to, so they're
                        // going to point us at another authority (based on a hostname, not IP address), so we have
                        // to resolve the IP address for that authority first. Once that's resolved, the resolution
                        // of the original DNS request will continue.
                        let mut cursor = Cursor::new(&ns_record.data[..]);
                        let nameserver_name_str_bytes = RecordName::read_and_advance(&mut cursor)?;
                        let Ok(nameserver_name_str) = std::str::from_utf8(&nameserver_name_str_bytes) else {
                            return Err(DnsError::InvalidByteInName);
                        };

                        info!(
                            "{}{} handed us off to {}",
                            " ".repeat(((recursion_depth) * 4).into()),
                            name_server_ip,
                            nameserver_name_str,
                        );

                        let new_query = Query {
                            domain_name: nameserver_name_str,
                            record_type: RecordType::A,
                        };
                        let name_server_resolved_packet =
                            new_query.resolve_with_depth(socket, recursion_depth + 1, rand_seed)?;
                        let Some(name_server_a_record) = name_server_resolved_packet.answers.get_first_a_record() else {
                            return Err(DnsError::UnknownDomainName);
                        };

                        name_server_host = nameserver_name_str.to_owned();
                        name_server_ip = name_server_a_record.ip_address();

                        info!(
                            "{}Resolved {} to {}",
                            " ".repeat(((recursion_depth + 1) * 4).into()),
                            nameserver_name_str,
                            name_server_ip,
                        )
                    } else {
                        return Err(DnsError::UnknownDomainName);
                    }
                }

                Err(error) => {
                    return Err(error);
                }
            }
        }
    }
}

/// Validate parsing of an incomplete header
#[test]
fn test_query_serialization() {
    let query = Query {
        domain_name: "example.com",
        record_type: RecordType::A,
    };

    let expected = [
        // Header                           Question...
        // ID Flag  Qs    Answ  Auth  Addl  example.com
        59, 108, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109,
        // ...Question
        // Type  Class
        0, 0, 1, 0, 1,
    ];

    // The first two bytes of a serialized query is the random ID. Ignore that.
    assert_eq!(
        query.serialize(Some(0)).unwrap_or_default().as_slice(),
        expected
    );
}

/// Validate the full flow of querying DNS with a mock socket.
#[test]
fn test_querying_domain_with_ns_delegation() -> Result<(), DnsError> {
    use crate::mock_data;
    use crate::socket::MockSocket;

    let data = mock_data::CAPTURED_DATA_FOR_TWITTER;

    let mut socket = MockSocket::bind("")?;
    socket.register_response_data(data);

    let query = Query {
        domain_name: "twitter.com",
        record_type: RecordType::A,
    };

    let mut boxed_socket: Box<dyn Socket<MockSocket>> = Box::new(socket);
    let packet = query.resolve(&mut boxed_socket, Some(0))?;

    let a_record = packet.answers.get_first_a_record().unwrap();
    assert_eq!(a_record.ip_address(), "104.244.42.193");
    assert_eq!(a_record.ttl, 1800);
    assert_eq!(a_record.r_class, 1);
    assert_eq!(a_record.r_type, RecordType::A);
    Ok(())
}
