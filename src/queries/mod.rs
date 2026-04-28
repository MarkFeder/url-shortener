//! SQL query constants for the URL shortener application.
//!
//! Centralizes all SQL queries by domain for better maintainability.
//! Each submodule owns the queries for one logical area; everything is
//! re-exported here so callers can keep using `crate::queries::Urls` etc.

mod schema;
mod users;
mod api_keys;
mod urls;
mod click_logs;
mod tags;

pub use api_keys::ApiKeys;
pub use click_logs::ClickLogs;
pub use schema::Schema;
pub use tags::{Tags, UrlTags};
pub use urls::Urls;
pub use users::Users;
