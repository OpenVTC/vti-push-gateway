//! vti-push-gateway library surface — the push wake-up gateway
//! (<https://trusttasks.org/binding/push/0.1>). The `main` binary is a thin
//! wrapper; integration tests drive [`api::router`] directly.

pub mod api;
pub mod controllers;
pub mod didcomm;
pub mod egress;
pub mod identity;
pub mod intake;
pub mod limits;
pub mod metrics;
pub mod proof;
pub mod relationships;
pub mod replay;
pub mod resolver;
pub mod secretfile;
pub mod sender;
pub mod store;
pub mod tsp;
pub mod types;
