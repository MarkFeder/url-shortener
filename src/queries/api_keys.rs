//! API key queries.

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

    pub const SELECT_BY_ID: &'static str =
        "SELECT id, user_id, key_hash, name, created_at, last_used_at, is_active FROM api_keys WHERE id = ?1";

    pub const COUNT_BY_ID_AND_USER: &'static str =
        "SELECT COUNT(*) FROM api_keys WHERE id = ?1 AND user_id = ?2";

    pub const SELECT_KEY_HASH_BY_ID: &'static str =
        "SELECT key_hash FROM api_keys WHERE id = ?1";
}
