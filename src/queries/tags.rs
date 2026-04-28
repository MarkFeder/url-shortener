//! Tag and URL-tag junction queries.

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

    /// Get all tags for multiple URLs in a single query
    /// Returns: (url_id, tag_id, tag_name, tag_user_id, tag_created_at)
    pub const SELECT_TAGS_FOR_URLS: &'static str = "
        SELECT ut.url_id, t.id, t.name, t.user_id, t.created_at
        FROM url_tags ut
        INNER JOIN tags t ON t.id = ut.tag_id
        WHERE ut.url_id IN (SELECT id FROM urls WHERE user_id = ?1)
        ORDER BY ut.url_id, t.name ASC";
}
