//! Schema-related queries for database setup and migrations.

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
            browser         TEXT,
            browser_version TEXT,
            os              TEXT,
            device_type     TEXT,
            referer_domain  TEXT,
            FOREIGN KEY (url_id) REFERENCES urls (id) ON DELETE CASCADE
        )";

    pub const ADD_BROWSER_TO_CLICK_LOGS: &'static str =
        "ALTER TABLE click_logs ADD COLUMN browser TEXT";

    pub const ADD_BROWSER_VERSION_TO_CLICK_LOGS: &'static str =
        "ALTER TABLE click_logs ADD COLUMN browser_version TEXT";

    pub const ADD_OS_TO_CLICK_LOGS: &'static str =
        "ALTER TABLE click_logs ADD COLUMN os TEXT";

    pub const ADD_DEVICE_TYPE_TO_CLICK_LOGS: &'static str =
        "ALTER TABLE click_logs ADD COLUMN device_type TEXT";

    pub const ADD_REFERER_DOMAIN_TO_CLICK_LOGS: &'static str =
        "ALTER TABLE click_logs ADD COLUMN referer_domain TEXT";

    pub const CREATE_CLICK_LOGS_URL_ID_INDEX: &'static str =
        "CREATE INDEX IF NOT EXISTS idx_click_logs_url_id ON click_logs (url_id)";

    pub const CREATE_CLICK_LOGS_URL_ID_CLICKED_AT_INDEX: &'static str =
        "CREATE INDEX IF NOT EXISTS idx_click_logs_url_id_clicked_at ON click_logs (url_id, clicked_at)";

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
