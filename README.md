[![codecov](https://codecov.io/gh/keehun/toy_dns/branch/main/graph/badge.svg?token=EK8CR0KEGJ)](https://codecov.io/gh/keehun/toy_dns)
[![Unit Tests](https://github.com/keehun/toy_dns/actions/workflows/unit_tests.yml/badge.svg)](https://github.com/keehun/toy_dns/actions/workflows/unit_tests.yml)

# `toy_dns`
`toy_dns` is a tool I've developed to hone my understanding of how DNS works as well as to improve my Rust skills. It is not (yet) close to being a full-fledged, mature recursive DNS resolver.

## Goals
* Be a full-fledged DNS client that can handle every record type and is compatible with the prominent servers out in the wild.
* Only use safe & stable Rust features.
* No panics. (Panics due to `.unwrap()` or assertions are allowed in tests.)
* Support modern DNS features such as DNS-over-TLS, DNS-over-HTTPS, and DNSSEC validation.
* Be a flexible yet easy-to-use CLI tool.

## Upcoming Features
Upcoming features are enumerated as issues on Github attached to [the "1.0" milestone](https://github.com/keehun/toy_dns/milestone/1).

## Installation

1. Clone this repository
2. `cargo build` or `cargo run <DOMAIN NAME>`

## Testing
`toy_dns` currently does not have any integration or E2E tests. It utilizes only unit tests to be executed with `cargo test --workspace`. [Issue #2](https://github.com/keehun/toy_dns/issues/2) aims to address this shortcoming.