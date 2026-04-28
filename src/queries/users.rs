//! User-related queries.

pub struct Users;

impl Users {
    pub const INSERT: &'static str =
        "INSERT INTO users (email) VALUES (?1)";

    pub const SELECT_BY_ID: &'static str =
        "SELECT id, email, created_at FROM users WHERE id = ?1";

    pub const COUNT_BY_EMAIL: &'static str =
        "SELECT COUNT(*) FROM users WHERE email = ?1";
}
