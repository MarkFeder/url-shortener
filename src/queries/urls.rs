//! URL-related queries for CRUD operations.

pub struct Urls;

impl Urls {
    pub const COUNT_BY_ID_AND_USER: &'static str =
        "SELECT COUNT(*) FROM urls WHERE id = ?1 AND user_id = ?2";
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

    pub const UPDATE_URL_BY_ID_AND_USER: &'static str =
        "UPDATE urls SET original_url = ?1, updated_at = datetime('now') WHERE id = ?2 AND user_id = ?3";

    pub const SELECT_SHORT_CODE_BY_ID: &'static str = "SELECT short_code FROM urls WHERE id = ?1";

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

    /// Search URLs by original URL and/or short code (case-insensitive)
    /// Parameters: ?1 = user_id, ?2 = url_pattern, ?3 = code_pattern, ?4 = limit
    pub const SEARCH: &'static str = "
        SELECT id, short_code, original_url, clicks, created_at, updated_at, expires_at, user_id
        FROM urls
        WHERE user_id = ?1
          AND (?2 IS NULL OR original_url LIKE '%' || ?2 || '%' COLLATE NOCASE)
          AND (?3 IS NULL OR short_code LIKE '%' || ?3 || '%' COLLATE NOCASE)
        ORDER BY created_at DESC
        LIMIT ?4";

    /// Count matching search results (mirrors SEARCH WHERE clause)
    /// Parameters: ?1 = user_id, ?2 = url_pattern, ?3 = code_pattern
    pub const COUNT_SEARCH: &'static str = "
        SELECT COUNT(*)
        FROM urls
        WHERE user_id = ?1
          AND (?2 IS NULL OR original_url LIKE '%' || ?2 || '%' COLLATE NOCASE)
          AND (?3 IS NULL OR short_code LIKE '%' || ?3 || '%' COLLATE NOCASE)";
}
