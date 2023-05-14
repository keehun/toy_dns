use clap::Parser;
use env_logger::Builder;
use log::{error, LevelFilter};
use std::io::{stdout, Write};
use std::net::UdpSocket;
use toy_dns_lib::errors::DnsError;
use toy_dns_lib::query::Query;
use toy_dns_lib::record::RecordType;
use toy_dns_lib::socket::Socket;

/// Arguments for toy_dns
#[derive(Parser, Debug)]
#[command(version, arg_required_else_help(true))]
struct Args {
    /// Name of the person to greet
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// Domain name to query
    domain_name: String,

    /// Random generator seed
    #[arg(short, long)]
    rand_seed: Option<usize>,
}

fn main() {
    let args = Args::parse();

    let logging_level = match args.verbose {
        true => LevelFilter::Info,
        false => LevelFilter::Off,
    };

    Builder::new()
        .format(|buf, record| {
            writeln!(
                buf,
                "[{}] {}",
                record.level(),
                // record.target(),
                record.args()
            )
        })
        .filter(None, logging_level)
        .init();

    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(socket) => socket,
        Err(error) => {
            error!("Failed to bind UDP socket to a local port. {}", error);
            std::process::exit(DnsError::SocketBind.exit_code());
        }
    };

    let mut boxed_socket: Box<dyn Socket<UdpSocket>> = Box::new(socket);
    std::process::exit(run::<UdpSocket>(args, &mut boxed_socket, &mut stdout()));
}

/// Run toy_dns with given arguments and logging level.
///
/// # Argument
/// * `args`: CLI arguments.
/// * `socket`: The socket (in a `Box`) to run toy_dns queries through.
/// * `stdout`: stdout to write to.
///
/// # Return
/// Returns the process exit code. 0 on success.
fn run<T>(args: Args, socket: &mut Box<dyn Socket<T>>, stdout: &mut impl Write) -> i32 {
    let query = Query {
        domain_name: &args.domain_name,
        record_type: RecordType::A,
    };

    match query.resolve(socket, args.rand_seed) {
        Ok(packet) => {
            _ = writeln!(stdout, "Answer:");
            _ = writeln!(stdout, "");
            for answer in packet.answers {
                let Ok(name) = std::str::from_utf8(&answer.name) else {
                    eprintln!("Could not decode record name in UTF8.");
                    return DnsError::InvalidByteInName.exit_code();
                };
                let address = answer.ip_address();
                _ = writeln!(
                    stdout,
                    "Found {} record for {} with address {} set to expire in {}",
                    answer.r_type, name, address, answer.ttl
                );
            }
            return 0;
        }
        Err(error) => {
            eprintln!("DNS request failed with {}", error);
            return error.exit_code();
        }
    }
}

#[cfg(test)]
use toy_dns_lib::socket::MockSocket;

#[cfg(test)]
use toy_dns_lib::mock_data;

/// Validate running the program with twitter.com
#[test]
fn test_running_toy_dns() -> Result<(), DnsError> {
    let args = Args {
        verbose: false,
        domain_name: "twitter.com".to_owned(),
        rand_seed: Some(0),
    };

    let data = mock_data::CAPTURED_DATA_FOR_TWITTER;

    let mut socket = MockSocket::bind("")?;
    socket.register_response_data(data);

    let mut stdout: Vec<u8> = Vec::new();

    let mut boxed_socket: Box<dyn Socket<MockSocket>> = Box::new(socket);

    assert_eq!(run::<MockSocket>(args, &mut boxed_socket, &mut stdout), 0);

    assert_eq!(
        String::from_utf8(stdout).unwrap(),
        "Answer:\n\nFound A record for twitter.com with address 104.244.42.193 set to expire in 1800\n"
    );

    Ok(())
}

/// Validate running the program with an invalid CLI argument results in an error.
#[test]
fn test_running_toy_dns_with_invalid_domain_name() -> Result<(), DnsError> {
    let args = Args {
        verbose: true,
        domain_name: "❌".to_owned(),
        rand_seed: Some(0),
    };

    let socket = MockSocket::bind("")?;

    let mut stdout: Vec<u8> = Vec::new();
    let mut boxed_socket: Box<dyn Socket<MockSocket>> = Box::new(socket);

    let result = run::<MockSocket>(args, &mut boxed_socket, &mut stdout);
    assert_eq!(result, DnsError::QuerySerialization.exit_code());

    Ok(())
}
