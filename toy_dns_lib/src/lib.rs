pub mod packet;
pub mod query;
pub mod record;

pub mod errors;
mod header;
mod question;
mod record_name;
mod root_servers;

pub mod socket;

// Normally, this should not be pub. However, I wanted to easily test main.rs using this mock data.
// I would usually recommend a multi-pronged approach of unit-testing, integrated testing,
// E2E testing, and human QA, but for this hobby project (for now), I wanted to just do unit
// testing.
pub mod mock_data;
