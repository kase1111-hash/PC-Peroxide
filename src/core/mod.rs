//! Core module containing fundamental types, configuration, and error handling.

pub mod config;
pub mod error;
pub mod types;

pub use config::Config;
pub use error::{Error, Result};
