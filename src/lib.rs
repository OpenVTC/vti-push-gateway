//! vti-push-gateway library surface — the push wake-up gateway
//! (<https://trusttasks.org/binding/push/0.1>). The `main` binary is a thin
//! wrapper; integration tests drive [`api::router`] directly.

pub mod api;
pub mod auth;
pub mod didcomm;
pub mod identity;
pub mod metrics;
pub mod resolver;
pub mod sender;
pub mod store;
pub mod types;
