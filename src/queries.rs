//! SQL query constants for the URL shortener application.
//!
//! Centralizes all SQL queries for better maintainability and consistency.

/// Schema-related queries for database setup and migrations.
pub struct Schema;

impl Schema {
    pub const CREATE_URLS_TABLE: &'static str = "
        CREATE TABLE IF NOT EXISTS urls (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            short_code      TEXT NOT NULL UNIQUE,
            original_url    TEXT NOT NULL,
            clicks          INTEGER NOT NULL DEFAULT 0,
            created_at      TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
            expires_at      TEXT
        )";

    pub const CREATE_SHORT_CODE_INDEX: &'static str =
        "CREATE INDEX IF NOT EXISTS idx_short_code ON urls (short_code)";

    pub const CREATE_CLICK_LOGS_TABLE: &'static str = "
        CREATE TABLE IF NOT EXISTS click_logs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            url_id          INTEGER NOT NULL,
            clicked_at      TEXT NOT NULL DEFAULT (datetime('now')),
            ip_address      TEXT,
            user_agent      TEXT,
            referer         TEXT,
            FOREIGN KEY (url_id) REFERENCES urls (id) ON DELETE CASCADE
        )";
}

/// URL-related queries for CRUD operations.
pub struct Urls;

impl Urls {
    pub const INSERT: &'static str =
        "INSERT INTO urls (short_code, original_url, expires_at) VALUES (?1, ?2, ?3)";

    pub const SELECT_BY_CODE: &'static str = "
        SELECT id, short_code, original_url, clicks, created_at, updated_at, expires_at
        FROM urls WHERE short_code = ?1";

    pub const SELECT_BY_ID: &'static str = "
        SELECT id, short_code, original_url, clicks, created_at, updated_at, expires_at
        FROM urls WHERE id = ?1";

    pub const COUNT_BY_CODE: &'static str = "SELECT COUNT(*) FROM urls WHERE short_code = ?1";

    pub const COUNT_ALL: &'static str = "SELECT COUNT(*) FROM urls";

    pub const DELETE_BY_ID: &'static str = "DELETE FROM urls WHERE id = ?1";

    pub const INCREMENT_CLICKS: &'static str =
        "UPDATE urls SET clicks = clicks + 1, updated_at = datetime('now') WHERE id = ?1";

    /// Returns the list query with the specified sort order.
    /// Use `ASC` or `DESC` for the sort_order parameter.
    pub fn list_with_order(sort_order: &str) -> String {
        format!(
            "SELECT id, short_code, original_url, clicks, created_at, updated_at, expires_at
             FROM urls
             ORDER BY created_at {}
             LIMIT ?1 OFFSET ?2",
            sort_order
        )
    }
}

/// Click log queries for analytics.
pub struct ClickLogs;

impl ClickLogs {
    pub const INSERT: &'static str =
        "INSERT INTO click_logs (url_id, ip_address, user_agent, referer) VALUES (?1, ?2, ?3, ?4)";

    pub const SELECT_BY_URL_ID: &'static str = "
        SELECT id, url_id, clicked_at, ip_address, user_agent, referer
        FROM click_logs
        WHERE url_id = ?1
        ORDER BY clicked_at DESC
        LIMIT ?2";
}
