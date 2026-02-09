//! Tag CRUD and URL-tag association services.

use rusqlite::params;

use super::helpers::{check_ownership, map_tag_row, map_url_row};
use crate::db::{get_conn, DbPool};
use crate::errors::AppError;
use crate::models::{Tag, Url};
use crate::queries::{Tags, UrlTags, Urls};

/// Create a new tag for a user
pub fn create_tag(pool: &DbPool, name: &str, user_id: i64) -> Result<Tag, AppError> {
    let conn = get_conn(pool)?;

    // Check if tag name already exists for this user
    let exists: i32 = conn
        .query_row(
            Tags::COUNT_BY_NAME_AND_USER,
            params![name, user_id],
            |row| row.get(0),
        )
        .unwrap_or(0);

    if exists > 0 {
        return Err(AppError::DuplicateCode(format!(
            "Tag '{}' already exists",
            name
        )));
    }

    conn.execute(Tags::INSERT, params![name, user_id])?;
    let tag_id = conn.last_insert_rowid();

    let tag = conn.query_row(Tags::SELECT_BY_ID, params![tag_id], map_tag_row)?;

    log::info!("Created tag '{}' for user {}", name, user_id);
    Ok(tag)
}

/// List all tags for a user
pub fn list_tags(pool: &DbPool, user_id: i64) -> Result<Vec<Tag>, AppError> {
    let conn = get_conn(pool)?;
    let mut stmt = conn.prepare(Tags::SELECT_BY_USER)?;

    let tags = stmt
        .query_map(params![user_id], map_tag_row)?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(tags)
}

/// Delete a tag (cascades to url_tags)
pub fn delete_tag(pool: &DbPool, tag_id: i64, user_id: i64) -> Result<(), AppError> {
    let conn = get_conn(pool)?;

    let rows_affected = conn.execute(Tags::DELETE_BY_ID_AND_USER, params![tag_id, user_id])?;

    if rows_affected == 0 {
        return Err(AppError::NotFound(format!(
            "Tag with ID '{}' not found",
            tag_id
        )));
    }

    log::info!("Deleted tag {} for user {}", tag_id, user_id);
    Ok(())
}

/// Add a tag to a URL
pub fn add_tag_to_url(
    pool: &DbPool,
    url_id: i64,
    tag_id: i64,
    user_id: i64,
) -> Result<(), AppError> {
    let conn = get_conn(pool)?;

    // Verify the URL belongs to the user
    if !check_ownership(&conn, Urls::COUNT_BY_ID_AND_USER, url_id, user_id)? {
        return Err(AppError::NotFound(format!(
            "URL with ID '{}' not found",
            url_id
        )));
    }

    // Verify the tag belongs to the user
    if !check_ownership(&conn, Tags::COUNT_BY_ID_AND_USER, tag_id, user_id)? {
        return Err(AppError::NotFound(format!(
            "Tag with ID '{}' not found",
            tag_id
        )));
    }

    // Check if the association already exists
    let already_tagged: i32 = conn
        .query_row(
            UrlTags::COUNT_BY_URL_AND_TAG,
            params![url_id, tag_id],
            |row| row.get(0),
        )
        .unwrap_or(0);

    if already_tagged > 0 {
        return Err(AppError::DuplicateCode(
            "URL already has this tag".to_string(),
        ));
    }

    conn.execute(UrlTags::INSERT, params![url_id, tag_id])?;

    log::info!(
        "Added tag {} to URL {} for user {}",
        tag_id,
        url_id,
        user_id
    );
    Ok(())
}

/// Remove a tag from a URL
pub fn remove_tag_from_url(
    pool: &DbPool,
    url_id: i64,
    tag_id: i64,
    user_id: i64,
) -> Result<(), AppError> {
    let conn = get_conn(pool)?;

    // Verify the URL belongs to the user
    if !check_ownership(&conn, Urls::COUNT_BY_ID_AND_USER, url_id, user_id)? {
        return Err(AppError::NotFound(format!(
            "URL with ID '{}' not found",
            url_id
        )));
    }

    // Verify the tag belongs to the user
    if !check_ownership(&conn, Tags::COUNT_BY_ID_AND_USER, tag_id, user_id)? {
        return Err(AppError::NotFound(format!(
            "Tag with ID '{}' not found",
            tag_id
        )));
    }

    let rows_affected = conn.execute(UrlTags::DELETE, params![url_id, tag_id])?;

    if rows_affected == 0 {
        return Err(AppError::NotFound(
            "URL does not have this tag".to_string(),
        ));
    }

    log::info!(
        "Removed tag {} from URL {} for user {}",
        tag_id,
        url_id,
        user_id
    );
    Ok(())
}

/// Get all tags for a URL
pub fn get_tags_for_url(pool: &DbPool, url_id: i64, user_id: i64) -> Result<Vec<Tag>, AppError> {
    let conn = get_conn(pool)?;

    // Verify the URL belongs to the user
    if !check_ownership(&conn, Urls::COUNT_BY_ID_AND_USER, url_id, user_id)? {
        return Err(AppError::NotFound(format!(
            "URL with ID '{}' not found",
            url_id
        )));
    }

    let mut stmt = conn.prepare(UrlTags::SELECT_TAGS_BY_URL)?;

    let tags = stmt
        .query_map(params![url_id], map_tag_row)?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(tags)
}

/// Get all URLs with a specific tag
pub fn get_urls_by_tag(pool: &DbPool, tag_id: i64, user_id: i64) -> Result<Vec<Url>, AppError> {
    let conn = get_conn(pool)?;

    // Verify the tag belongs to the user
    if !check_ownership(&conn, Tags::COUNT_BY_ID_AND_USER, tag_id, user_id)? {
        return Err(AppError::NotFound(format!(
            "Tag with ID '{}' not found",
            tag_id
        )));
    }

    let mut stmt = conn.prepare(UrlTags::SELECT_URLS_BY_TAG)?;

    let urls = stmt
        .query_map(params![tag_id, user_id], map_url_row)?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(urls)
}

/// Get all URLs with a specific tag, including all tags for each URL
/// This is an optimized version that avoids N+1 queries by fetching all tags
/// for the URLs in a single additional query.
pub fn get_urls_by_tag_with_tags(
    pool: &DbPool,
    tag_id: i64,
    user_id: i64,
) -> Result<Vec<(Url, Vec<Tag>)>, AppError> {
    let conn = get_conn(pool)?;

    // Verify the tag belongs to the user
    if !check_ownership(&conn, Tags::COUNT_BY_ID_AND_USER, tag_id, user_id)? {
        return Err(AppError::NotFound(format!(
            "Tag with ID '{}' not found",
            tag_id
        )));
    }

    // First, get all URLs with this tag
    let mut stmt = conn.prepare(UrlTags::SELECT_URLS_BY_TAG)?;
    let urls: Vec<Url> = stmt
        .query_map(params![tag_id, user_id], map_url_row)?
        .collect::<Result<Vec<_>, _>>()?;

    if urls.is_empty() {
        return Ok(vec![]);
    }

    // Build a map of url_id -> tags using a single query
    let mut url_tags_map: std::collections::HashMap<i64, Vec<Tag>> =
        std::collections::HashMap::new();

    // Get all tags for all URLs owned by this user
    let mut tag_stmt = conn.prepare(UrlTags::SELECT_TAGS_FOR_URLS)?;
    let tag_rows = tag_stmt.query_map(params![user_id], |row| {
        Ok((
            row.get::<_, i64>(0)?, // url_id
            Tag {
                id: row.get(1)?,
                name: row.get(2)?,
                user_id: row.get(3)?,
                created_at: row.get(4)?,
            },
        ))
    })?;

    for result in tag_rows {
        let (url_id, tag) = result?;
        url_tags_map.entry(url_id).or_default().push(tag);
    }

    // Combine URLs with their tags
    let result: Vec<(Url, Vec<Tag>)> = urls
        .into_iter()
        .map(|url| {
            let tags = url_tags_map.remove(&url.id).unwrap_or_default();
            (url, tags)
        })
        .collect();

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::CreateUrlRequest;
    use crate::services::{create_url, register_user};
    use crate::test_utils::setup_test_db;

    #[test]
    fn test_create_tag() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let tag = create_tag(&pool, "Important", user.id).unwrap();
        assert_eq!(tag.name, "Important");
        assert_eq!(tag.user_id, user.id);
    }

    #[test]
    fn test_create_duplicate_tag() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        create_tag(&pool, "Important", user.id).unwrap();
        let result = create_tag(&pool, "Important", user.id);
        assert!(matches!(result, Err(AppError::DuplicateCode(_))));
    }

    #[test]
    fn test_list_tags() {
        let pool = setup_test_db();

        let (user1, _) = register_user(&pool, "user1@example.com").unwrap();
        let (user2, _) = register_user(&pool, "user2@example.com").unwrap();

        // Create tags for user1
        create_tag(&pool, "Work", user1.id).unwrap();
        create_tag(&pool, "Personal", user1.id).unwrap();

        // Create tag for user2
        create_tag(&pool, "Other", user2.id).unwrap();

        // User1 should only see their tags
        let user1_tags = list_tags(&pool, user1.id).unwrap();
        assert_eq!(user1_tags.len(), 2);

        // User2 should only see their tags
        let user2_tags = list_tags(&pool, user2.id).unwrap();
        assert_eq!(user2_tags.len(), 1);
        assert_eq!(user2_tags[0].name, "Other");
    }

    #[test]
    fn test_delete_tag() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let tag = create_tag(&pool, "ToDelete", user.id).unwrap();

        // Delete should succeed
        delete_tag(&pool, tag.id, user.id).unwrap();

        // Tag should be gone
        let tags = list_tags(&pool, user.id).unwrap();
        assert!(tags.is_empty());
    }

    #[test]
    fn test_add_tag_to_url() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let tag = create_tag(&pool, "Important", user.id).unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("tagged".to_string()),
            expires_in_hours: None,
        };
        let url = create_url(&pool, &request, 7, user.id).unwrap();

        // Add tag to URL
        add_tag_to_url(&pool, url.id, tag.id, user.id).unwrap();

        // Verify tag is associated
        let tags = get_tags_for_url(&pool, url.id, user.id).unwrap();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].name, "Important");
    }

    #[test]
    fn test_add_duplicate_tag_to_url() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let tag = create_tag(&pool, "Important", user.id).unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("tagged2".to_string()),
            expires_in_hours: None,
        };
        let url = create_url(&pool, &request, 7, user.id).unwrap();

        // Add tag first time
        add_tag_to_url(&pool, url.id, tag.id, user.id).unwrap();

        // Try to add same tag again - should fail
        let result = add_tag_to_url(&pool, url.id, tag.id, user.id);
        assert!(matches!(result, Err(AppError::DuplicateCode(_))));
    }

    #[test]
    fn test_remove_tag_from_url() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let tag = create_tag(&pool, "Important", user.id).unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("toremove".to_string()),
            expires_in_hours: None,
        };
        let url = create_url(&pool, &request, 7, user.id).unwrap();

        // Add and then remove tag
        add_tag_to_url(&pool, url.id, tag.id, user.id).unwrap();
        remove_tag_from_url(&pool, url.id, tag.id, user.id).unwrap();

        // Verify tag is removed
        let tags = get_tags_for_url(&pool, url.id, user.id).unwrap();
        assert!(tags.is_empty());
    }

    #[test]
    fn test_get_urls_by_tag() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let tag = create_tag(&pool, "Work", user.id).unwrap();
        let other_tag = create_tag(&pool, "Personal", user.id).unwrap();

        // Create URLs and tag them
        let request1 = CreateUrlRequest {
            url: "https://work1.com".to_string(),
            custom_code: Some("work1".to_string()),
            expires_in_hours: None,
        };
        let url1 = create_url(&pool, &request1, 7, user.id).unwrap();
        add_tag_to_url(&pool, url1.id, tag.id, user.id).unwrap();

        let request2 = CreateUrlRequest {
            url: "https://work2.com".to_string(),
            custom_code: Some("work2".to_string()),
            expires_in_hours: None,
        };
        let url2 = create_url(&pool, &request2, 7, user.id).unwrap();
        add_tag_to_url(&pool, url2.id, tag.id, user.id).unwrap();

        let request3 = CreateUrlRequest {
            url: "https://personal.com".to_string(),
            custom_code: Some("personal".to_string()),
            expires_in_hours: None,
        };
        let url3 = create_url(&pool, &request3, 7, user.id).unwrap();
        add_tag_to_url(&pool, url3.id, other_tag.id, user.id).unwrap();

        // Get URLs by "Work" tag
        let work_urls = get_urls_by_tag(&pool, tag.id, user.id).unwrap();
        assert_eq!(work_urls.len(), 2);

        // Get URLs by "Personal" tag
        let personal_urls = get_urls_by_tag(&pool, other_tag.id, user.id).unwrap();
        assert_eq!(personal_urls.len(), 1);
    }

    #[test]
    fn test_get_urls_by_tag_with_tags() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let tag1 = create_tag(&pool, "Work", user.id).unwrap();
        let tag2 = create_tag(&pool, "Important", user.id).unwrap();

        // Create URL with both tags
        let request = CreateUrlRequest {
            url: "https://work-important.com".to_string(),
            custom_code: Some("multi_tag".to_string()),
            expires_in_hours: None,
        };
        let url = create_url(&pool, &request, 7, user.id).unwrap();
        add_tag_to_url(&pool, url.id, tag1.id, user.id).unwrap();
        add_tag_to_url(&pool, url.id, tag2.id, user.id).unwrap();

        // Get URLs by "Work" tag with all tags included
        let urls_with_tags = get_urls_by_tag_with_tags(&pool, tag1.id, user.id).unwrap();
        assert_eq!(urls_with_tags.len(), 1);

        let (returned_url, tags) = &urls_with_tags[0];
        assert_eq!(returned_url.id, url.id);
        assert_eq!(tags.len(), 2); // Should have both Work and Important tags

        // Verify both tags are present
        let tag_names: Vec<&str> = tags.iter().map(|t| t.name.as_str()).collect();
        assert!(tag_names.contains(&"Work"));
        assert!(tag_names.contains(&"Important"));
    }

    #[test]
    fn test_tag_ownership() {
        let pool = setup_test_db();

        let (user1, _) = register_user(&pool, "user1@example.com").unwrap();
        let (user2, _) = register_user(&pool, "user2@example.com").unwrap();

        // User1 creates a tag
        let tag = create_tag(&pool, "Private", user1.id).unwrap();

        // User2 cannot delete user1's tag
        let result = delete_tag(&pool, tag.id, user2.id);
        assert!(matches!(result, Err(AppError::NotFound(_))));

        // User2 cannot use user1's tag
        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("user2url".to_string()),
            expires_in_hours: None,
        };
        let url = create_url(&pool, &request, 7, user2.id).unwrap();

        let result = add_tag_to_url(&pool, url.id, tag.id, user2.id);
        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    #[test]
    fn test_delete_tag_cascades_to_url_tags() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let tag = create_tag(&pool, "Temporary", user.id).unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("cascade".to_string()),
            expires_in_hours: None,
        };
        let url = create_url(&pool, &request, 7, user.id).unwrap();

        // Add tag to URL
        add_tag_to_url(&pool, url.id, tag.id, user.id).unwrap();

        // Delete the tag
        delete_tag(&pool, tag.id, user.id).unwrap();

        // URL should have no tags now
        let tags = get_tags_for_url(&pool, url.id, user.id).unwrap();
        assert!(tags.is_empty());
    }
}
