use crate::errors::DnsError;
use std::collections::HashMap;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::UdpSocket;

pub trait Socket<T> {
    /// Bind the socket to the provided address
    ///
    /// # Argument
    /// * `addr`: The (local) address to bind to.
    fn bind(addr: &str) -> Result<T, DnsError>
    where
        Self: Sized;

    /// Send the given buffer to the provided address. Upon success will return the size of the
    /// sent buffer.
    ///
    /// # Arguments
    /// * `buf`: The buffer to send.
    /// * `addr`: The address to send `buf` to.
    fn send<'a>(&'a mut self, buf: &'a [u8], addr: &str) -> Result<usize, DnsError>;

    /// Wait for data on the socket. Upon success will return the size of the received data.
    ///
    /// # Argument
    /// * `buf`: The buffer to populate when data is received.
    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), DnsError>;
}

impl Socket<UdpSocket> for UdpSocket {
    fn bind(addr: &str) -> Result<UdpSocket, DnsError>
    where
        Self: Sized,
    {
        let new_socket = UdpSocket::bind(addr);
        match new_socket {
            Ok(socket) => return Ok(socket),
            Err(_) => return Err(DnsError::SocketBind),
        }
    }

    fn send<'a>(&'a mut self, buf: &'a [u8], addr: &str) -> Result<usize, DnsError> {
        match self.send_to(buf, addr) {
            Ok(size) => Ok(size),
            Err(_) => Err(DnsError::SocketSend),
        }
    }

    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), DnsError> {
        match self.recv_from(buf) {
            Ok(size_and_addr) => Ok(size_and_addr),
            Err(_) => Err(DnsError::SocketRead),
        }
    }
}

/// Key used to match send calls with the right preconfigured response
#[derive(Clone, Eq, PartialEq, Hash, Copy)]
pub struct MockKey<'a> {
    pub query_bytes: &'a [u8],
    pub server_ip: &'a str,
}

/// Data with which to configure MockSocket.
pub struct MockData<'a> {
    pub data: &'a [u8],
}

/// A socket object that vendors preconfigured responses.
pub struct MockSocket<'a> {
    /// The map of all preconfigured responses for this mock socket.
    response_data: HashMap<&'a MockKey<'a>, &'a MockData<'a>>,

    /// The next response to serve when socket gets recv_from() called.
    next_response: Option<&'a MockData<'a>>,
}

impl<'a> MockSocket<'a> {
    /// Preconfigure the mock socket with data
    ///
    /// # Argument
    /// * `data`: The data with which to configure the mock socket.
    pub fn register_response_data(&mut self, data: &'a [(MockKey, MockData)]) {
        self.response_data = HashMap::new();
        for (key, value) in data {
            self.response_data.insert(key, value);
        }
    }
}

impl Default for MockSocket<'_> {
    fn default() -> Self {
        MockSocket {
            response_data: HashMap::new(),
            next_response: None,
        }
    }
}

impl Socket<MockSocket<'_>> for MockSocket<'_> {
    fn bind(_addr: &str) -> Result<MockSocket<'static>, DnsError>
    where
        Self: Sized,
    {
        Ok(MockSocket::default())
    }

    fn send<'a>(&'a mut self, buf: &[u8], addr: &'a str) -> Result<usize, DnsError> {
        let key = MockKey {
            query_bytes: buf,
            server_ip: addr,
        };

        // Look up the request in the preconfigured data and get the associated response, if any.
        let Some(response) = self.response_data.get(&key) else {
            return Err(DnsError::SocketSend);
        };

        // Next time recv_from() is called on the mock socket, it will return the response from
        // the lookup above.
        self.next_response = Some(*response);

        Ok(buf.len())
    }

    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), DnsError> {
        let Some(response) = self.next_response else {
            return Err(DnsError::SocketRead);
        };

        buf.copy_from_slice(response.data);

        // Address & port doesn't matter for the time being as the result is not used by toy_dns.
        let zero_addr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
        return Ok((0, SocketAddr::new(zero_addr, 0)));
    }
}

/*
Tests for MockSocket functionality
 */

/// Ensure MockSocket vendors the correct response
#[test]
fn test_mock_socket_send_and_receive_preconfigured_data() -> Result<(), DnsError> {
    let query_1 = &[12, 34];
    let addr_1 = &"1.2.3.4:0";
    let data_1 = &[0xAB; 1024];

    let query_2 = &[56, 78];
    let addr_2 = &"5.6.7.8:0";
    let data_2 = &[0xEF; 1024];

    let mut socket = MockSocket::bind("")?;

    let data = &[
        (
            MockKey {
                query_bytes: query_1,
                server_ip: addr_1,
            },
            MockData { data: data_1 },
        ),
        (
            MockKey {
                query_bytes: query_2,
                server_ip: addr_2,
            },
            MockData { data: data_2 },
        ),
    ];

    socket.register_response_data(data);

    assert!(socket.send(query_1, addr_1).is_ok());

    let mut buf = [0; 1024];
    assert!(socket.recv_from(&mut buf).is_ok());

    assert_eq!(&buf, data_1);

    Ok(())
}

/// Ensure MockSocket errors out when the sent data is not recognized.
#[test]
fn test_mock_socket_send_unrecognized_data() -> Result<(), DnsError> {
    let query_1 = &[12, 34];
    let addr_1 = &"1.2.3.4:0";
    let data_1 = &[0xAB; 1024];

    let query_2 = &[56, 78];
    let addr_2 = &"5.6.7.8:0";

    let mut socket = MockSocket::bind("")?;

    let data = &[(
        MockKey {
            query_bytes: query_1,
            server_ip: addr_1,
        },
        MockData { data: data_1 },
    )];

    socket.register_response_data(data);

    // Because we didn't preconfigure the mock socket with query_2 and addr_2, this should fail.
    assert!(socket.send(query_2, addr_2).is_err());

    Ok(())
}

/// Ensure MockSocket errors out when the sent query is unrecognized even though the server IP is.
#[test]
fn test_mock_socket_send_unrecognized_query() -> Result<(), DnsError> {
    let query_1 = &[12, 34];
    let addr_1 = &"1.2.3.4:0";
    let data_1 = &[0xAB; 1024];

    let query_2 = &[56, 78];

    let mut socket = MockSocket::bind("")?;

    let data = &[(
        MockKey {
            query_bytes: query_1,
            server_ip: addr_1,
        },
        MockData { data: data_1 },
    )];

    socket.register_response_data(data);

    // Because we didn't preconfigure the mock socket with query_2 and addr_2, this should fail.
    assert!(socket.send(query_2, addr_1).is_err());

    Ok(())
}

/// Ensure MockSocket errors out when the server IP is unrecognized even though the query is.
#[test]
fn test_mock_socket_send_unrecognized_server_ip() -> Result<(), DnsError> {
    let query_1 = &[12, 34];
    let addr_1 = &"1.2.3.4:0";
    let data_1 = &[0xAB; 1024];

    let addr_2 = &"5.6.7.8:0";

    let mut socket = MockSocket::bind("")?;

    let data = &[(
        MockKey {
            query_bytes: query_1,
            server_ip: addr_1,
        },
        MockData { data: data_1 },
    )];

    socket.register_response_data(data);

    // Because we didn't preconfigure the mock socket with query_2 and addr_2, this should fail.
    assert!(socket.send(query_1, addr_2).is_err());

    Ok(())
}

/// If MockSocket is not preconfigured with responses, it should return an error.
#[test]
fn test_mock_socket_receive_without_preconfiguring() -> Result<(), DnsError> {
    let socket = MockSocket::bind("")?;

    let mut buf = [0; 1024];
    assert!(socket.recv_from(&mut buf).is_err());

    Ok(())
}
