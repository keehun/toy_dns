# `toy_dns`
`toy_dns` is a tool I've developed to hone my understanding of how DNS works. It is not (yet) close to being a full-fledged, mature recursive DNS resolver.

## Goals
* Be a full-fledged DNS client that can handle every record type and is compatible with the prominent servers out in the wild.
* Only use safe & stable Rust features.
* No panics. (Panics due to `.unwrap()` or assertions are allowed in tests.)
* Support modern DNS features such as DNS-over-TLS, DNS-over-HTTPS, and DNSSEC validation.
* Be a flexible yet easy-to-use CLI tool.

## Upcoming Features
Upcoming features are enumerated as issues on Github.

## Installation

1. Clone this repository
2. `cargo build` or `cargo run <DOMAIN NAME>`

## Testing
`toy_dns` currently does not have any integration or E2E tests. It utilizes only unit tests to be executed with `cargo test --workspace`.