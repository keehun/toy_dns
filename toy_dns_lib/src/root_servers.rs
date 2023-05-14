use phf::phf_ordered_map;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

pub struct RootServerName(pub &'static str);

/// The authoratative name servers as declared by IANA at https://www.iana.org/domains/root/servers
const ROOT_SERVERS_AND_IPS: phf::OrderedMap<&'static str, RootServerName> = phf_ordered_map! {
    "198.41.0.4" => RootServerName("a.root-servers.net"),
    "192.33.4.12" => RootServerName("c.root-servers.net"),
    "199.7.91.13" => RootServerName("d.root-servers.net"),
    "192.203.230.10" => RootServerName("e.root-servers.net"),
    "192.5.5.241" => RootServerName("f.root-servers.net"),
    "192.112.36.4" => RootServerName("g.root-servers.net"),
    "198.97.190.53" => RootServerName("h.root-servers.net"),
    "192.36.148.17" => RootServerName("i.root-servers.net"),
    "192.58.128.30" => RootServerName("j.root-servers.net"),
    "193.0.14.129" => RootServerName("k.root-servers.net"),
    "199.7.83.42" => RootServerName("l.root-servers.net"),
    "202.12.27.33" => RootServerName("m.root-servers.net"),
};

pub struct RootServer {}

impl RootServer {
    pub fn random(random_seed: Option<usize>) -> (&'static &'static str, &'static RootServerName) {
        let range = 0..ROOT_SERVERS_AND_IPS.len();
        let random_index = match random_seed {
            None => rand::thread_rng().gen_range(range),
            Some(value) => ChaCha8Rng::seed_from_u64(value as u64).gen_range(range),
        };
        ROOT_SERVERS_AND_IPS.into_iter().nth(random_index).unwrap()
    }
}

#[test]
/// Because `RootServer::random()` uses unwrap(), ensure it doesn't panic.
fn test_random_root_server_selection_without_seed_does_not_panic() {
    for _ in 0..10_000 {
        assert!(std::panic::catch_unwind(|| RootServer::random(None)).is_ok());
    }
}

#[test]
/// Ensure that seeded random root server selection remains consistent run-to-run. Other tests
/// depend on this behavior.
fn test_random_root_server_selection_with_seed_is_consistent() {
    for _ in 0..100 {
        assert_eq!(RootServer::random(Some(0)).0, &"192.58.128.30",);
    }
}
