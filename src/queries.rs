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
            expires_at      TEXT,
            user_id         INTEGER,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
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

    pub const CREATE_USERS_TABLE: &'static str = "
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            email       TEXT NOT NULL UNIQUE,
            created_at  TEXT NOT NULL DEFAULT (datetime('now'))
        )";

    pub const CREATE_API_KEYS_TABLE: &'static str = "
        CREATE TABLE IF NOT EXISTS api_keys (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL,
            key_hash     TEXT NOT NULL UNIQUE,
            name         TEXT NOT NULL,
            created_at   TEXT NOT NULL DEFAULT (datetime('now')),
            last_used_at TEXT,
            is_active    INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )";

    pub const TABLE_EXISTS: &'static str =
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1";

    pub const ADD_USER_ID_TO_URLS: &'static str =
        "ALTER TABLE urls ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE CASCADE";

    pub const COLUMN_EXISTS: &'static str =
        "SELECT COUNT(*) FROM pragma_table_info(?1) WHERE name=?2";

    pub const CREATE_TAGS_TABLE: &'static str = "
        CREATE TABLE IF NOT EXISTS tags (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            user_id     INTEGER NOT NULL,
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            UNIQUE (name, user_id)
        )";

    pub const CREATE_URL_TAGS_TABLE: &'static str = "
        CREATE TABLE IF NOT EXISTS url_tags (
            url_id  INTEGER NOT NULL,
            tag_id  INTEGER NOT NULL,
            PRIMARY KEY (url_id, tag_id),
            FOREIGN KEY (url_id) REFERENCES urls (id) ON DELETE CASCADE,
            FOREIGN KEY (tag_id) REFERENCES tags (id) ON DELETE CASCADE
        )";
}

/// User-related queries.
pub struct Users;

impl Users {
    pub const INSERT: &'static str =
        "INSERT INTO users (email) VALUES (?1)";

    pub const SELECT_BY_EMAIL: &'static str =
        "SELECT id, email, created_at FROM users WHERE email = ?1";

    pub const SELECT_BY_ID: &'static str =
        "SELECT id, email, created_at FROM users WHERE id = ?1";

    pub const COUNT_BY_EMAIL: &'static str =
        "SELECT COUNT(*) FROM users WHERE email = ?1";
}

/// API key queries.
pub struct ApiKeys;

impl ApiKeys {
    pub const INSERT: &'static str =
        "INSERT INTO api_keys (user_id, key_hash, name) VALUES (?1, ?2, ?3)";

    pub const SELECT_BY_HASH: &'static str = "
        SELECT ak.id, ak.user_id, ak.key_hash, ak.name, ak.created_at, ak.last_used_at, ak.is_active
        FROM api_keys ak
        WHERE ak.key_hash = ?1 AND ak.is_active = 1";

    pub const SELECT_BY_USER: &'static str = "
        SELECT id, user_id, key_hash, name, created_at, last_used_at, is_active
        FROM api_keys
        WHERE user_id = ?1
        ORDER BY created_at DESC";

    pub const DEACTIVATE: &'static str =
        "UPDATE api_keys SET is_active = 0 WHERE id = ?1 AND user_id = ?2";

    pub const UPDATE_LAST_USED: &'static str =
        "UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?1";

    pub const SELECT_BY_ID_AND_USER: &'static str =
        "SELECT id, user_id, key_hash, name, created_at, last_used_at, is_active FROM api_keys WHERE id = ?1 AND user_id = ?2";

    pub const SELECT_BY_ID: &'static str =
        "SELECT id, user_id, key_hash, name, created_at, last_used_at, is_active FROM api_keys WHERE id = ?1";

    pub const COUNT_BY_ID_AND_USER: &'static str =
        "SELECT COUNT(*) FROM api_keys WHERE id = ?1 AND user_id = ?2";
}

/// URL-related queries for CRUD operations.
pub struct Urls;

impl Urls {
    pub const INSERT: &'static str =
        "INSERT INTO urls (short_code, original_url, expires_at, user_id) VALUES (?1, ?2, ?3, ?4)";

    pub const SELECT_BY_CODE: &'static str = "
        SELECT id, short_code, original_url, clicks, created_at, updated_at, expires_at, user_id
        FROM urls WHERE short_code = ?1";

    pub const SELECT_BY_ID: &'static str = "
        SELECT id, short_code, original_url, clicks, created_at, updated_at, expires_at, user_id
        FROM urls WHERE id = ?1";

    pub const SELECT_BY_ID_AND_USER: &'static str = "
        SELECT id, short_code, original_url, clicks, created_at, updated_at, expires_at, user_id
        FROM urls WHERE id = ?1 AND user_id = ?2";

    pub const COUNT_BY_CODE: &'static str = "SELECT COUNT(*) FROM urls WHERE short_code = ?1";

    pub const COUNT_ALL: &'static str = "SELECT COUNT(*) FROM urls";

    pub const COUNT_BY_USER: &'static str = "SELECT COUNT(*) FROM urls WHERE user_id = ?1";

    pub const DELETE_BY_ID: &'static str = "DELETE FROM urls WHERE id = ?1";

    pub const DELETE_BY_ID_AND_USER: &'static str = "DELETE FROM urls WHERE id = ?1 AND user_id = ?2";

    pub const INCREMENT_CLICKS: &'static str =
        "UPDATE urls SET clicks = clicks + 1, updated_at = datetime('now') WHERE id = ?1";

    /// Returns the list query with the specified sort order for a specific user.
    pub fn list_by_user_with_order(sort_order: &str) -> String {
        format!(
            "SELECT id, short_code, original_url, clicks, created_at, updated_at, expires_at, user_id
             FROM urls
             WHERE user_id = ?1
             ORDER BY created_at {}
             LIMIT ?2 OFFSET ?3",
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

/// Tag-related queries.
pub struct Tags;

impl Tags {
    pub const INSERT: &'static str =
        "INSERT INTO tags (name, user_id) VALUES (?1, ?2)";

    pub const SELECT_BY_ID: &'static str = "
        SELECT id, name, user_id, created_at
        FROM tags WHERE id = ?1";

    pub const SELECT_BY_ID_AND_USER: &'static str = "
        SELECT id, name, user_id, created_at
        FROM tags WHERE id = ?1 AND user_id = ?2";

    pub const SELECT_BY_USER: &'static str = "
        SELECT id, name, user_id, created_at
        FROM tags WHERE user_id = ?1
        ORDER BY name ASC";

    pub const DELETE_BY_ID_AND_USER: &'static str =
        "DELETE FROM tags WHERE id = ?1 AND user_id = ?2";

    pub const COUNT_BY_NAME_AND_USER: &'static str =
        "SELECT COUNT(*) FROM tags WHERE name = ?1 AND user_id = ?2";

    pub const COUNT_BY_ID_AND_USER: &'static str =
        "SELECT COUNT(*) FROM tags WHERE id = ?1 AND user_id = ?2";
}

/// URL-Tag junction table queries.
pub struct UrlTags;

impl UrlTags {
    pub const INSERT: &'static str =
        "INSERT INTO url_tags (url_id, tag_id) VALUES (?1, ?2)";

    pub const DELETE: &'static str =
        "DELETE FROM url_tags WHERE url_id = ?1 AND tag_id = ?2";

    pub const SELECT_TAGS_BY_URL: &'static str = "
        SELECT t.id, t.name, t.user_id, t.created_at
        FROM tags t
        INNER JOIN url_tags ut ON t.id = ut.tag_id
        WHERE ut.url_id = ?1
        ORDER BY t.name ASC";

    pub const SELECT_URLS_BY_TAG: &'static str = "
        SELECT u.id, u.short_code, u.original_url, u.clicks, u.created_at, u.updated_at, u.expires_at, u.user_id
        FROM urls u
        INNER JOIN url_tags ut ON u.id = ut.url_id
        WHERE ut.tag_id = ?1 AND u.user_id = ?2
        ORDER BY u.created_at DESC";

    pub const COUNT_BY_URL_AND_TAG: &'static str =
        "SELECT COUNT(*) FROM url_tags WHERE url_id = ?1 AND tag_id = ?2";
}
