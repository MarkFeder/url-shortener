//! Bulk create and delete operations for URLs.

use crate::cache::AppCache;
use crate::db::DbPool;
use crate::errors::AppError;
use crate::models::{
    BulkCreateItemResult, BulkCreateUrlItem, BulkCreateUrlResponse, BulkDeleteItemResult,
    BulkDeleteUrlResponse, BulkItemError, BulkOperationStatus, CreateUrlRequest, CreateUrlResponse,
};

use super::urls::{create_url, delete_url_with_cache};

/// Convert an AppError to an error code string
fn error_to_code(err: &AppError) -> String {
    match err {
        AppError::NotFound(_) => "NOT_FOUND".to_string(),
        AppError::ValidationError(_) => "VALIDATION_ERROR".to_string(),
        AppError::DatabaseError(_) => "DATABASE_ERROR".to_string(),
        AppError::DuplicateCode(_) => "DUPLICATE_CODE".to_string(),
        AppError::ExpiredUrl(_) => "EXPIRED_URL".to_string(),
        AppError::InternalError(_) => "INTERNAL_ERROR".to_string(),
        AppError::Unauthorized(_) => "UNAUTHORIZED".to_string(),
        AppError::Forbidden(_) => "FORBIDDEN".to_string(),
        AppError::EmailAlreadyExists(_) => "EMAIL_ALREADY_EXISTS".to_string(),
    }
}

/// Bulk create multiple URLs
///
/// Processes each URL individually, collecting successes and failures.
/// Uses a transaction for consistency but commits individual operations.
pub fn bulk_create_urls(
    pool: &DbPool,
    items: &[BulkCreateUrlItem],
    code_length: usize,
    user_id: i64,
    base_url: &str,
) -> Result<BulkCreateUrlResponse, AppError> {
    let mut results = Vec::with_capacity(items.len());
    let mut succeeded = 0;
    let mut failed = 0;

    for (index, item) in items.iter().enumerate() {
        // Convert BulkCreateUrlItem to CreateUrlRequest
        let request = CreateUrlRequest {
            url: item.url.clone(),
            custom_code: item.custom_code.clone(),
            expires_in_hours: item.expires_in_hours,
        };

        match create_url(pool, &request, code_length, user_id) {
            Ok(url) => {
                succeeded += 1;
                results.push(BulkCreateItemResult {
                    index,
                    success: true,
                    data: Some(CreateUrlResponse {
                        short_code: url.short_code.clone(),
                        short_url: format!("{}/{}", base_url, url.short_code),
                        original_url: url.original_url,
                        created_at: url.created_at,
                        expires_at: url.expires_at,
                    }),
                    error: None,
                });
            }
            Err(err) => {
                failed += 1;
                results.push(BulkCreateItemResult {
                    index,
                    success: false,
                    data: None,
                    error: Some(BulkItemError {
                        code: error_to_code(&err),
                        message: err.to_string(),
                    }),
                });
            }
        }
    }

    let status = if failed == 0 {
        BulkOperationStatus::Success
    } else if succeeded == 0 {
        BulkOperationStatus::Failed
    } else {
        BulkOperationStatus::PartialSuccess
    };

    log::info!(
        "Bulk create: {} total, {} succeeded, {} failed (user: {})",
        items.len(),
        succeeded,
        failed,
        user_id
    );

    Ok(BulkCreateUrlResponse {
        status,
        total: items.len(),
        succeeded,
        failed,
        results,
    })
}

/// Bulk delete multiple URLs by ID
///
/// Processes each deletion individually, collecting successes and failures.
pub fn bulk_delete_urls(
    pool: &DbPool,
    ids: &[i64],
    user_id: i64,
) -> Result<BulkDeleteUrlResponse, AppError> {
    bulk_delete_urls_with_cache(pool, None, ids, user_id)
}

/// Bulk delete multiple URLs by ID with cache invalidation
///
/// Processes each deletion individually, collecting successes and failures.
pub fn bulk_delete_urls_with_cache(
    pool: &DbPool,
    cache: Option<&AppCache>,
    ids: &[i64],
    user_id: i64,
) -> Result<BulkDeleteUrlResponse, AppError> {
    let mut results = Vec::with_capacity(ids.len());
    let mut succeeded = 0;
    let mut failed = 0;

    for &id in ids {
        match delete_url_with_cache(pool, cache, id, user_id) {
            Ok(()) => {
                succeeded += 1;
                results.push(BulkDeleteItemResult {
                    id,
                    success: true,
                    error: None,
                });
            }
            Err(err) => {
                failed += 1;
                results.push(BulkDeleteItemResult {
                    id,
                    success: false,
                    error: Some(BulkItemError {
                        code: error_to_code(&err),
                        message: err.to_string(),
                    }),
                });
            }
        }
    }

    let status = if failed == 0 {
        BulkOperationStatus::Success
    } else if succeeded == 0 {
        BulkOperationStatus::Failed
    } else {
        BulkOperationStatus::PartialSuccess
    };

    log::info!(
        "Bulk delete: {} total, {} succeeded, {} failed (user: {})",
        ids.len(),
        succeeded,
        failed,
        user_id
    );

    Ok(BulkDeleteUrlResponse {
        status,
        total: ids.len(),
        succeeded,
        failed,
        results,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::AppCache;
    use crate::models::{BulkCreateUrlItem, CreateUrlRequest};
    use crate::services::{create_url, get_url_by_code, get_url_by_id, register_user};
    use crate::test_utils::setup_test_db;

    #[test]
    fn test_bulk_create_all_success() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let items = vec![
            BulkCreateUrlItem {
                url: "https://example1.com".to_string(),
                custom_code: Some("bulk1".to_string()),
                expires_in_hours: None,
            },
            BulkCreateUrlItem {
                url: "https://example2.com".to_string(),
                custom_code: Some("bulk2".to_string()),
                expires_in_hours: None,
            },
        ];

        let response = bulk_create_urls(&pool, &items, 7, user.id, "http://localhost").unwrap();

        assert_eq!(response.status, BulkOperationStatus::Success);
        assert_eq!(response.total, 2);
        assert_eq!(response.succeeded, 2);
        assert_eq!(response.failed, 0);
        assert_eq!(response.results.len(), 2);

        // Verify all items succeeded
        for result in &response.results {
            assert!(result.success);
            assert!(result.data.is_some());
            assert!(result.error.is_none());
        }

        // Verify URLs were created
        assert!(get_url_by_code(&pool, "bulk1").is_ok());
        assert!(get_url_by_code(&pool, "bulk2").is_ok());
    }

    #[test]
    fn test_bulk_create_partial_duplicate() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        // First create a URL with code "existing"
        let request = CreateUrlRequest {
            url: "https://existing.com".to_string(),
            custom_code: Some("existing".to_string()),
            expires_in_hours: None,
        };
        create_url(&pool, &request, 7, user.id).unwrap();

        // Now try bulk create with one duplicate
        let items = vec![
            BulkCreateUrlItem {
                url: "https://new.com".to_string(),
                custom_code: Some("newcode".to_string()),
                expires_in_hours: None,
            },
            BulkCreateUrlItem {
                url: "https://duplicate.com".to_string(),
                custom_code: Some("existing".to_string()), // duplicate!
                expires_in_hours: None,
            },
        ];

        let response = bulk_create_urls(&pool, &items, 7, user.id, "http://localhost").unwrap();

        assert_eq!(response.status, BulkOperationStatus::PartialSuccess);
        assert_eq!(response.total, 2);
        assert_eq!(response.succeeded, 1);
        assert_eq!(response.failed, 1);

        // First item should succeed
        assert!(response.results[0].success);
        assert!(response.results[0].data.is_some());

        // Second item should fail with duplicate error
        assert!(!response.results[1].success);
        assert!(response.results[1].error.is_some());
        assert_eq!(response.results[1].error.as_ref().unwrap().code, "DUPLICATE_CODE");
    }

    #[test]
    fn test_bulk_create_auto_generate_codes() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        // Create items without custom codes
        let items = vec![
            BulkCreateUrlItem {
                url: "https://auto1.com".to_string(),
                custom_code: None,
                expires_in_hours: None,
            },
            BulkCreateUrlItem {
                url: "https://auto2.com".to_string(),
                custom_code: None,
                expires_in_hours: None,
            },
            BulkCreateUrlItem {
                url: "https://auto3.com".to_string(),
                custom_code: None,
                expires_in_hours: None,
            },
        ];

        let response = bulk_create_urls(&pool, &items, 7, user.id, "http://localhost").unwrap();

        assert_eq!(response.status, BulkOperationStatus::Success);
        assert_eq!(response.succeeded, 3);

        // All codes should be unique
        let codes: Vec<&str> = response
            .results
            .iter()
            .map(|r| r.data.as_ref().unwrap().short_code.as_str())
            .collect();

        let unique_codes: std::collections::HashSet<&str> = codes.iter().cloned().collect();
        assert_eq!(unique_codes.len(), 3);
    }

    #[test]
    fn test_bulk_delete_all_success() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        // Create some URLs
        let mut ids = vec![];
        for i in 0..3 {
            let request = CreateUrlRequest {
                url: format!("https://delete{}.com", i),
                custom_code: Some(format!("del{}", i)),
                expires_in_hours: None,
            };
            let url = create_url(&pool, &request, 7, user.id).unwrap();
            ids.push(url.id);
        }

        // Bulk delete
        let response = bulk_delete_urls(&pool, &ids, user.id).unwrap();

        assert_eq!(response.status, BulkOperationStatus::Success);
        assert_eq!(response.total, 3);
        assert_eq!(response.succeeded, 3);
        assert_eq!(response.failed, 0);

        // Verify all were deleted
        for id in &ids {
            let result = get_url_by_id(&pool, *id, user.id);
            assert!(matches!(result, Err(AppError::NotFound(_))));
        }
    }

    #[test]
    fn test_bulk_delete_partial_not_found() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        // Create one URL
        let request = CreateUrlRequest {
            url: "https://exists.com".to_string(),
            custom_code: Some("exists".to_string()),
            expires_in_hours: None,
        };
        let url = create_url(&pool, &request, 7, user.id).unwrap();

        // Try to delete existing + non-existing
        let ids = vec![url.id, 99999, 99998];
        let response = bulk_delete_urls(&pool, &ids, user.id).unwrap();

        assert_eq!(response.status, BulkOperationStatus::PartialSuccess);
        assert_eq!(response.total, 3);
        assert_eq!(response.succeeded, 1);
        assert_eq!(response.failed, 2);

        // First should succeed
        assert!(response.results[0].success);

        // Others should fail
        assert!(!response.results[1].success);
        assert_eq!(response.results[1].error.as_ref().unwrap().code, "NOT_FOUND");
        assert!(!response.results[2].success);
    }

    #[test]
    fn test_bulk_delete_respects_ownership() {
        let pool = setup_test_db();

        let (user1, _) = register_user(&pool, "user1@example.com").unwrap();
        let (user2, _) = register_user(&pool, "user2@example.com").unwrap();

        // Create URLs for user1
        let request = CreateUrlRequest {
            url: "https://user1.com".to_string(),
            custom_code: Some("user1url".to_string()),
            expires_in_hours: None,
        };
        let url = create_url(&pool, &request, 7, user1.id).unwrap();

        // User2 tries to bulk delete user1's URL
        let response = bulk_delete_urls(&pool, &[url.id], user2.id).unwrap();

        assert_eq!(response.status, BulkOperationStatus::Failed);
        assert_eq!(response.failed, 1);
        assert!(!response.results[0].success);

        // URL should still exist
        assert!(get_url_by_code(&pool, "user1url").is_ok());
    }

    #[test]
    fn test_bulk_delete_invalidates_cache() {
        let pool = setup_test_db();
        let cache = AppCache::default();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        // Create multiple URLs
        let mut ids = vec![];
        for i in 0..3 {
            let request = CreateUrlRequest {
                url: format!("https://example{}.com", i),
                custom_code: Some(format!("bulk_cache_{}", i)),
                expires_in_hours: None,
            };
            let url = create_url(&pool, &request, 7, user.id).unwrap();
            ids.push(url.id);

            // Populate the cache
            crate::services::get_url_by_code_cached(&pool, &cache, &format!("bulk_cache_{}", i)).unwrap();
        }

        // Verify all are cached
        for i in 0..3 {
            assert!(cache.get_url(&format!("bulk_cache_{}", i)).is_some());
        }

        // Bulk delete with cache invalidation
        bulk_delete_urls_with_cache(&pool, Some(&cache), &ids, user.id).unwrap();

        // All cache entries should be invalidated
        for i in 0..3 {
            assert!(cache.get_url(&format!("bulk_cache_{}", i)).is_none());
        }
    }
}
