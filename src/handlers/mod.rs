//! HTTP request handlers for the URL shortener API.
//!
//! Defines all route handlers and configures the routing table.

mod auth;
mod urls;
mod bulk;
mod tags;
mod analytics;
mod redirect;
mod health;

use actix_web::web;

/// Configure all application routes
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            // Auth routes (register is public)
            .service(
                web::scope("/auth")
                    .service(auth::register)
                    .service(auth::create_api_key)
                    .service(auth::list_api_keys)
                    .service(auth::revoke_api_key),
            )
            // Tag routes
            .service(tags::create_tag)
            .service(tags::list_tags)
            .service(tags::delete_tag)
            .service(tags::get_urls_by_tag)
            .service(tags::add_tag_to_url)
            .service(tags::remove_tag_from_url)
            // Bulk URL operations (must be registered before single-item routes)
            .service(bulk::bulk_create_urls)
            .service(bulk::bulk_delete_urls)
            // URL routes (all protected)
            .service(urls::create_short_url)
            .service(urls::search_urls)
            .service(urls::list_urls)
            .service(urls::get_url_by_id)
            .service(urls::delete_url_by_id)
            .service(analytics::get_url_analytics_timeline)
            .service(analytics::get_url_analytics_referrers)
            .service(analytics::get_url_analytics_browsers)
            .service(analytics::get_url_analytics_devices)
            .service(urls::get_url_stats)
            .service(urls::get_url_qr_code),
    )
    // Register specific routes before catch-all route
    .service(health::health_check)
    .service(redirect::redirect_to_url);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::AppCache;
    use crate::config::Config;
    use crate::db::DbPool;
    use crate::models::{
        ApiKeyListResponse, BulkOperationStatus, CreateApiKeyResponse, CreateUrlRequest,
        CreateUrlResponse, RegisterResponse, TagListResponse, TagResponse, TimelineResponse,
        UrlListResponse, UrlResponse, UrlsByTagResponse, BrowserBreakdownResponse,
        DeviceBreakdownResponse, ReferrerBreakdownResponse,
    };
    use crate::services;
    use crate::test_utils::{setup_test_pool, test_cache, test_config};
    use actix_web::{test, App};

    async fn setup_test_app(
        pool: DbPool,
    ) -> impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    > {
        let config = test_config();
        let cache = test_cache();

        test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .app_data(web::Data::new(config))
                .app_data(web::Data::new(cache))
                .configure(configure_routes),
        )
        .await
    }

    #[actix_rt::test]
    async fn test_health_check() {
        let pool = setup_test_pool();
        let app = setup_test_app(pool).await;

        let req = test::TestRequest::get().uri("/health").to_request();
        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;

        assert!(resp.status().is_success());
    }

    #[actix_rt::test]
    async fn test_register_user() {
        let pool = setup_test_pool();
        let app = setup_test_app(pool).await;

        let req = test::TestRequest::post()
            .uri("/api/auth/register")
            .set_json(serde_json::json!({
                "email": "test@example.com"
            }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);

        let body: RegisterResponse = test::read_body_json(resp).await;
        assert_eq!(body.email, "test@example.com");
        assert!(body.api_key.starts_with("usk_"));
    }

    #[actix_rt::test]
    async fn test_create_url_requires_auth() {
        let pool = setup_test_pool();
        let app = setup_test_app(pool).await;

        let req = test::TestRequest::post()
            .uri("/api/shorten")
            .set_json(serde_json::json!({
                "url": "https://example.com"
            }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    #[actix_rt::test]
    async fn test_create_and_list_urls() {
        let pool = setup_test_pool();

        let (_, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let app = setup_test_app(pool).await;

        // Create a short URL
        let req = test::TestRequest::post()
            .uri("/api/shorten")
            .insert_header(("X-API-Key", api_key.clone()))
            .set_json(serde_json::json!({
                "url": "https://example.com",
                "custom_code": "test"
            }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);

        // List URLs
        let req = test::TestRequest::get()
            .uri("/api/urls")
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let body: UrlListResponse = test::read_body_json(resp).await;
        assert_eq!(body.total, 1);
        assert_eq!(body.urls[0].short_code, "test");
    }

    #[actix_rt::test]
    async fn test_redirect() {
        let pool = setup_test_pool();

        let (user, _) = services::register_user(&pool, "test@example.com").unwrap();
        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("redirect_test".to_string()),
            expires_in_hours: None,
        };
        services::create_url(&pool, &request, 7, user.id).unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::get()
            .uri("/redirect_test")
            .to_request();
        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;

        assert_eq!(resp.status(), 301);
    }

    #[actix_rt::test]
    async fn test_api_key_management() {
        let pool = setup_test_pool();

        let (_, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let app = setup_test_app(pool).await;

        // Create a new API key
        let req = test::TestRequest::post()
            .uri("/api/auth/keys")
            .insert_header(("X-API-Key", api_key.clone()))
            .set_json(serde_json::json!({
                "name": "Test Key"
            }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);

        let body: CreateApiKeyResponse = test::read_body_json(resp).await;
        assert_eq!(body.name, "Test Key");

        // List API keys
        let req = test::TestRequest::get()
            .uri("/api/auth/keys")
            .insert_header(("X-API-Key", api_key.clone()))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let body: ApiKeyListResponse = test::read_body_json(resp).await;
        assert_eq!(body.keys.len(), 2);

        // Revoke the new key
        let key_id = body.keys.iter().find(|k| k.name == "Test Key").unwrap().id;

        let req = test::TestRequest::delete()
            .uri(&format!("/api/auth/keys/{}", key_id))
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_rt::test]
    async fn test_url_ownership_isolation() {
        let pool = setup_test_pool();

        let (user1, api_key1) = services::register_user(&pool, "user1@example.com").unwrap();
        let (_, api_key2) = services::register_user(&pool, "user2@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("user1_url".to_string()),
            expires_in_hours: None,
        };
        let url = services::create_url(&pool, &request, 7, user1.id).unwrap();

        let app = setup_test_app(pool).await;

        // User1 can access their URL
        let req = test::TestRequest::get()
            .uri(&format!("/api/urls/{}", url.id))
            .insert_header(("X-API-Key", api_key1))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        // User2 cannot access user1's URL
        let req = test::TestRequest::get()
            .uri(&format!("/api/urls/{}", url.id))
            .insert_header(("X-API-Key", api_key2))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    // ========================================================================
    // Bulk Operation Handler Tests
    // ========================================================================

    #[actix_rt::test]
    async fn test_bulk_create_endpoint() {
        let pool = setup_test_pool();

        let (_, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::post()
            .uri("/api/urls/bulk")
            .insert_header(("X-API-Key", api_key))
            .set_json(serde_json::json!({
                "urls": [
                    { "url": "https://example1.com", "custom_code": "bulk_e1" },
                    { "url": "https://example2.com", "custom_code": "bulk_e2" }
                ]
            }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);

        let body: crate::models::BulkCreateUrlResponse = test::read_body_json(resp).await;
        assert_eq!(body.status, BulkOperationStatus::Success);
        assert_eq!(body.total, 2);
        assert_eq!(body.succeeded, 2);
        assert_eq!(body.failed, 0);
    }

    #[actix_rt::test]
    async fn test_bulk_create_requires_auth() {
        let pool = setup_test_pool();
        let app = setup_test_app(pool).await;

        let req = test::TestRequest::post()
            .uri("/api/urls/bulk")
            .set_json(serde_json::json!({
                "urls": [
                    { "url": "https://example.com" }
                ]
            }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    #[actix_rt::test]
    async fn test_bulk_create_validates_limit() {
        let pool = setup_test_pool();

        let (_, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let app = setup_test_app(pool).await;

        let urls: Vec<serde_json::Value> = (0..101)
            .map(|i| serde_json::json!({ "url": format!("https://example{}.com", i) }))
            .collect();

        let req = test::TestRequest::post()
            .uri("/api/urls/bulk")
            .insert_header(("X-API-Key", api_key))
            .set_json(serde_json::json!({ "urls": urls }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_rt::test]
    async fn test_bulk_delete_endpoint() {
        let pool = setup_test_pool();

        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let mut ids = vec![];
        for i in 0..2 {
            let request = CreateUrlRequest {
                url: format!("https://todelete{}.com", i),
                custom_code: Some(format!("todel{}", i)),
                expires_in_hours: None,
            };
            let url = services::create_url(&pool, &request, 7, user.id).unwrap();
            ids.push(url.id);
        }

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::delete()
            .uri("/api/urls/bulk")
            .insert_header(("X-API-Key", api_key))
            .set_json(serde_json::json!({ "ids": ids }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body: crate::models::BulkDeleteUrlResponse = test::read_body_json(resp).await;
        assert_eq!(body.status, BulkOperationStatus::Success);
        assert_eq!(body.total, 2);
        assert_eq!(body.succeeded, 2);
    }

    #[actix_rt::test]
    async fn test_bulk_operations_return_207_on_partial() {
        let pool = setup_test_pool();

        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://existing.com".to_string(),
            custom_code: Some("exists207".to_string()),
            expires_in_hours: None,
        };
        let url = services::create_url(&pool, &request, 7, user.id).unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::delete()
            .uri("/api/urls/bulk")
            .insert_header(("X-API-Key", api_key))
            .set_json(serde_json::json!({ "ids": [url.id, 99999] }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 207);

        let body: crate::models::BulkDeleteUrlResponse = test::read_body_json(resp).await;
        assert_eq!(body.status, BulkOperationStatus::PartialSuccess);
        assert_eq!(body.succeeded, 1);
        assert_eq!(body.failed, 1);
    }

    // ========================================================================
    // Tag Handler Tests
    // ========================================================================

    #[actix_rt::test]
    async fn test_create_tag_endpoint() {
        let pool = setup_test_pool();

        let (_, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::post()
            .uri("/api/tags")
            .insert_header(("X-API-Key", api_key))
            .set_json(serde_json::json!({
                "name": "Important"
            }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);

        let body: TagResponse = test::read_body_json(resp).await;
        assert_eq!(body.name, "Important");
    }

    #[actix_rt::test]
    async fn test_list_tags_endpoint() {
        let pool = setup_test_pool();

        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();
        services::create_tag(&pool, "Work", user.id).unwrap();
        services::create_tag(&pool, "Personal", user.id).unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::get()
            .uri("/api/tags")
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let body: TagListResponse = test::read_body_json(resp).await;
        assert_eq!(body.tags.len(), 2);
    }

    #[actix_rt::test]
    async fn test_delete_tag_endpoint() {
        let pool = setup_test_pool();

        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();
        let tag = services::create_tag(&pool, "ToDelete", user.id).unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::delete()
            .uri(&format!("/api/tags/{}", tag.id))
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_rt::test]
    async fn test_add_tag_to_url_endpoint() {
        let pool = setup_test_pool();

        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();
        let tag = services::create_tag(&pool, "Important", user.id).unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("tag_test".to_string()),
            expires_in_hours: None,
        };
        let url = services::create_url(&pool, &request, 7, user.id).unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::post()
            .uri(&format!("/api/urls/{}/tags", url.id))
            .insert_header(("X-API-Key", api_key))
            .set_json(serde_json::json!({
                "tag_id": tag.id
            }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);
    }

    #[actix_rt::test]
    async fn test_tag_endpoints_require_auth() {
        let pool = setup_test_pool();
        let app = setup_test_app(pool).await;

        // Try to create tag without auth
        let req = test::TestRequest::post()
            .uri("/api/tags")
            .set_json(serde_json::json!({
                "name": "Test"
            }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);

        // Try to list tags without auth
        let req = test::TestRequest::get().uri("/api/tags").to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    #[actix_rt::test]
    async fn test_get_urls_by_tag_endpoint() {
        let pool = setup_test_pool();

        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();
        let tag = services::create_tag(&pool, "Work", user.id).unwrap();

        let request1 = CreateUrlRequest {
            url: "https://work1.com".to_string(),
            custom_code: Some("bytag1".to_string()),
            expires_in_hours: None,
        };
        let url1 = services::create_url(&pool, &request1, 7, user.id).unwrap();
        services::add_tag_to_url(&pool, url1.id, tag.id, user.id).unwrap();

        let request2 = CreateUrlRequest {
            url: "https://work2.com".to_string(),
            custom_code: Some("bytag2".to_string()),
            expires_in_hours: None,
        };
        let url2 = services::create_url(&pool, &request2, 7, user.id).unwrap();
        services::add_tag_to_url(&pool, url2.id, tag.id, user.id).unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::get()
            .uri(&format!("/api/tags/{}/urls", tag.id))
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let body: UrlsByTagResponse = test::read_body_json(resp).await;
        assert_eq!(body.urls.len(), 2);
    }

    // ========================================================================
    // QR Code Handler Tests
    // ========================================================================

    #[actix_rt::test]
    async fn test_get_qr_code_png() {
        let pool = setup_test_pool();

        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("qr_test".to_string()),
            expires_in_hours: None,
        };
        let url = services::create_url(&pool, &request, 7, user.id).unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::get()
            .uri(&format!("/api/urls/{}/qr", url.id))
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let content_type = resp.headers().get("content-type").unwrap();
        assert_eq!(content_type, "image/png");

        let body = test::read_body(resp).await;
        assert!(body.starts_with(&[0x89, 0x50, 0x4E, 0x47]));
    }

    #[actix_rt::test]
    async fn test_get_qr_code_svg() {
        let pool = setup_test_pool();

        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("qr_svg_test".to_string()),
            expires_in_hours: None,
        };
        let url = services::create_url(&pool, &request, 7, user.id).unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::get()
            .uri(&format!("/api/urls/{}/qr?format=svg", url.id))
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let content_type = resp.headers().get("content-type").unwrap();
        assert_eq!(content_type, "image/svg+xml");

        let body = test::read_body(resp).await;
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("<svg"));
    }

    #[actix_rt::test]
    async fn test_get_qr_code_with_size() {
        let pool = setup_test_pool();

        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("qr_size_test".to_string()),
            expires_in_hours: None,
        };
        let url = services::create_url(&pool, &request, 7, user.id).unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::get()
            .uri(&format!("/api/urls/{}/qr?size=512", url.id))
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_rt::test]
    async fn test_get_qr_code_requires_auth() {
        let pool = setup_test_pool();

        let (user, _) = services::register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("qr_auth_test".to_string()),
            expires_in_hours: None,
        };
        let url = services::create_url(&pool, &request, 7, user.id).unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::get()
            .uri(&format!("/api/urls/{}/qr", url.id))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    #[actix_rt::test]
    async fn test_get_qr_code_not_found() {
        let pool = setup_test_pool();

        let (_, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::get()
            .uri("/api/urls/99999/qr")
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    #[actix_rt::test]
    async fn test_get_qr_code_respects_ownership() {
        let pool = setup_test_pool();

        let (user1, _) = services::register_user(&pool, "user1@example.com").unwrap();
        let (_, api_key2) = services::register_user(&pool, "user2@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("qr_owner_test".to_string()),
            expires_in_hours: None,
        };
        let url = services::create_url(&pool, &request, 7, user1.id).unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::get()
            .uri(&format!("/api/urls/{}/qr", url.id))
            .insert_header(("X-API-Key", api_key2))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    // ========================================================================
    // Search Handler Tests
    // ========================================================================

    #[actix_rt::test]
    async fn test_search_urls_by_original_url() {
        let pool = setup_test_pool();

        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let urls_data = [
            ("https://github.com/rust", "gh1"),
            ("https://github.com/tokio", "gh2"),
            ("https://docs.rs/actix", "docs"),
        ];

        for (url, code) in urls_data {
            let request = CreateUrlRequest {
                url: url.to_string(),
                custom_code: Some(code.to_string()),
                expires_in_hours: None,
            };
            services::create_url(&pool, &request, 7, user.id).unwrap();
        }

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::get()
            .uri("/api/urls/search?q=github")
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let body: UrlListResponse = test::read_body_json(resp).await;
        assert_eq!(body.total, 2);
    }

    #[actix_rt::test]
    async fn test_search_urls_by_short_code() {
        let pool = setup_test_pool();

        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let urls_data = [
            ("https://example1.com", "proj-alpha"),
            ("https://example2.com", "proj-beta"),
            ("https://example3.com", "docs-main"),
        ];

        for (url, code) in urls_data {
            let request = CreateUrlRequest {
                url: url.to_string(),
                custom_code: Some(code.to_string()),
                expires_in_hours: None,
            };
            services::create_url(&pool, &request, 7, user.id).unwrap();
        }

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::get()
            .uri("/api/urls/search?code=proj")
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let body: UrlListResponse = test::read_body_json(resp).await;
        assert_eq!(body.total, 2);
    }

    #[actix_rt::test]
    async fn test_search_urls_combined_filters() {
        let pool = setup_test_pool();

        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let urls_data = [
            ("https://github.com/project", "gh-proj"),
            ("https://github.com/other", "gh-other"),
            ("https://gitlab.com/project", "gl-proj"),
        ];

        for (url, code) in urls_data {
            let request = CreateUrlRequest {
                url: url.to_string(),
                custom_code: Some(code.to_string()),
                expires_in_hours: None,
            };
            services::create_url(&pool, &request, 7, user.id).unwrap();
        }

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::get()
            .uri("/api/urls/search?q=github&code=proj")
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let body: UrlListResponse = test::read_body_json(resp).await;
        assert_eq!(body.total, 1);
        assert_eq!(body.urls[0].short_code, "gh-proj");
    }

    #[actix_rt::test]
    async fn test_search_urls_requires_parameter() {
        let pool = setup_test_pool();

        let (_, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::get()
            .uri("/api/urls/search")
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_rt::test]
    async fn test_search_urls_requires_auth() {
        let pool = setup_test_pool();
        let app = setup_test_app(pool).await;

        let req = test::TestRequest::get()
            .uri("/api/urls/search?q=test")
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    #[actix_rt::test]
    async fn test_search_urls_respects_ownership() {
        let pool = setup_test_pool();

        let (user1, api_key1) = services::register_user(&pool, "user1@example.com").unwrap();
        let (user2, api_key2) = services::register_user(&pool, "user2@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://secret.example.com".to_string(),
            custom_code: Some("secret1".to_string()),
            expires_in_hours: None,
        };
        services::create_url(&pool, &request, 7, user1.id).unwrap();

        let request = CreateUrlRequest {
            url: "https://secret.example.com".to_string(),
            custom_code: Some("secret2".to_string()),
            expires_in_hours: None,
        };
        services::create_url(&pool, &request, 7, user2.id).unwrap();

        let app = setup_test_app(pool).await;

        // User1 searches
        let req = test::TestRequest::get()
            .uri("/api/urls/search?q=secret")
            .insert_header(("X-API-Key", api_key1))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        let body: UrlListResponse = test::read_body_json(resp).await;
        assert_eq!(body.total, 1);
        assert_eq!(body.urls[0].short_code, "secret1");

        // User2 searches
        let req = test::TestRequest::get()
            .uri("/api/urls/search?q=secret")
            .insert_header(("X-API-Key", api_key2))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        let body: UrlListResponse = test::read_body_json(resp).await;
        assert_eq!(body.total, 1);
        assert_eq!(body.urls[0].short_code, "secret2");
    }

    // ========================================================================
    // Analytics Handler Tests
    // ========================================================================

    #[actix_rt::test]
    async fn test_analytics_timeline_endpoint() {
        let pool = setup_test_pool();

        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("analytics_tl".to_string()),
            expires_in_hours: None,
        };
        let url = services::create_url(&pool, &request, 7, user.id).unwrap();

        for _ in 0..3 {
            services::record_click(&pool, url.id, Some("127.0.0.1"), None, None).unwrap();
        }

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::get()
            .uri(&format!("/api/urls/{}/analytics/timeline?period=daily&limit=7", url.id))
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let body: TimelineResponse = test::read_body_json(resp).await;
        assert_eq!(body.period, "daily");
        assert!(!body.data.is_empty());
        assert_eq!(body.data[0].count, 3);
    }

    #[actix_rt::test]
    async fn test_analytics_referrers_endpoint() {
        let pool = setup_test_pool();

        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("analytics_ref".to_string()),
            expires_in_hours: None,
        };
        let url = services::create_url(&pool, &request, 7, user.id).unwrap();

        services::record_click(&pool, url.id, None, None, Some("https://google.com/search")).unwrap();
        services::record_click(&pool, url.id, None, None, Some("https://twitter.com/post")).unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::get()
            .uri(&format!("/api/urls/{}/analytics/referrers", url.id))
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let body: ReferrerBreakdownResponse = test::read_body_json(resp).await;
        assert!(!body.data.is_empty());
    }

    #[actix_rt::test]
    async fn test_analytics_browsers_endpoint() {
        let pool = setup_test_pool();

        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("analytics_br".to_string()),
            expires_in_hours: None,
        };
        let url = services::create_url(&pool, &request, 7, user.id).unwrap();

        let chrome_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        services::record_click(&pool, url.id, None, Some(chrome_ua), None).unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::get()
            .uri(&format!("/api/urls/{}/analytics/browsers", url.id))
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let body: BrowserBreakdownResponse = test::read_body_json(resp).await;
        assert!(!body.data.is_empty());
    }

    #[actix_rt::test]
    async fn test_analytics_devices_endpoint() {
        let pool = setup_test_pool();

        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("analytics_dev".to_string()),
            expires_in_hours: None,
        };
        let url = services::create_url(&pool, &request, 7, user.id).unwrap();

        let desktop_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        services::record_click(&pool, url.id, None, Some(desktop_ua), None).unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::get()
            .uri(&format!("/api/urls/{}/analytics/devices", url.id))
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let body: DeviceBreakdownResponse = test::read_body_json(resp).await;
        assert!(!body.data.is_empty());
    }

    #[actix_rt::test]
    async fn test_analytics_requires_auth() {
        let pool = setup_test_pool();
        let app = setup_test_app(pool).await;

        let endpoints = [
            "/api/urls/1/analytics/timeline",
            "/api/urls/1/analytics/referrers",
            "/api/urls/1/analytics/browsers",
            "/api/urls/1/analytics/devices",
        ];

        for endpoint in endpoints {
            let req = test::TestRequest::get().uri(endpoint).to_request();
            let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
            assert_eq!(resp.status(), 401, "Endpoint {} should require auth", endpoint);
        }
    }

    #[actix_rt::test]
    async fn test_analytics_not_found() {
        let pool = setup_test_pool();
        let (_, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::get()
            .uri("/api/urls/99999/analytics/timeline")
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    #[actix_rt::test]
    async fn test_analytics_timeline_invalid_period() {
        let pool = setup_test_pool();

        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("bad_period".to_string()),
            expires_in_hours: None,
        };
        let url = services::create_url(&pool, &request, 7, user.id).unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::get()
            .uri(&format!("/api/urls/{}/analytics/timeline?period=monthly", url.id))
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    // ========================================================================
    // New Auth Handler Tests
    // ========================================================================

    #[actix_rt::test]
    async fn test_register_duplicate_email_returns_error() {
        let pool = setup_test_pool();
        services::register_user(&pool, "dup@example.com").unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::post()
            .uri("/api/auth/register")
            .set_json(serde_json::json!({ "email": "dup@example.com" }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 409);
    }

    #[actix_rt::test]
    async fn test_register_invalid_email_returns_400() {
        let pool = setup_test_pool();
        let app = setup_test_app(pool).await;

        let req = test::TestRequest::post()
            .uri("/api/auth/register")
            .set_json(serde_json::json!({ "email": "not-an-email" }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_rt::test]
    async fn test_list_api_keys_requires_auth() {
        let pool = setup_test_pool();
        let app = setup_test_app(pool).await;

        let req = test::TestRequest::get()
            .uri("/api/auth/keys")
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    #[actix_rt::test]
    async fn test_revoke_api_key_not_found() {
        let pool = setup_test_pool();
        let (_, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::delete()
            .uri("/api/auth/keys/99999")
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    #[actix_rt::test]
    async fn test_revoke_api_key_requires_auth() {
        let pool = setup_test_pool();
        let app = setup_test_app(pool).await;

        let req = test::TestRequest::delete()
            .uri("/api/auth/keys/1")
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    // ========================================================================
    // New URL Handler Tests
    // ========================================================================

    #[actix_rt::test]
    async fn test_create_url_with_custom_code() {
        let pool = setup_test_pool();
        let (_, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::post()
            .uri("/api/shorten")
            .insert_header(("X-API-Key", api_key))
            .set_json(serde_json::json!({
                "url": "https://example.com",
                "custom_code": "mycode"
            }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);

        let body: CreateUrlResponse = test::read_body_json(resp).await;
        assert_eq!(body.short_code, "mycode");
    }

    #[actix_rt::test]
    async fn test_create_url_with_expiration() {
        let pool = setup_test_pool();
        let (_, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::post()
            .uri("/api/shorten")
            .insert_header(("X-API-Key", api_key))
            .set_json(serde_json::json!({
                "url": "https://example.com",
                "custom_code": "exptest",
                "expires_in_hours": 24
            }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);

        let body: CreateUrlResponse = test::read_body_json(resp).await;
        assert!(body.expires_at.is_some());
    }

    #[actix_rt::test]
    async fn test_create_url_invalid_url_format() {
        let pool = setup_test_pool();
        let (_, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::post()
            .uri("/api/shorten")
            .insert_header(("X-API-Key", api_key))
            .set_json(serde_json::json!({
                "url": "not-a-valid-url"
            }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_rt::test]
    async fn test_create_url_duplicate_code() {
        let pool = setup_test_pool();
        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://first.com".to_string(),
            custom_code: Some("dupcode".to_string()),
            expires_in_hours: None,
        };
        services::create_url(&pool, &request, 7, user.id).unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::post()
            .uri("/api/shorten")
            .insert_header(("X-API-Key", api_key))
            .set_json(serde_json::json!({
                "url": "https://second.com",
                "custom_code": "dupcode"
            }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 409);
    }

    #[actix_rt::test]
    async fn test_get_url_by_id_not_found() {
        let pool = setup_test_pool();
        let (_, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::get()
            .uri("/api/urls/99999")
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    #[actix_rt::test]
    async fn test_get_url_by_id_requires_auth() {
        let pool = setup_test_pool();
        let app = setup_test_app(pool).await;

        let req = test::TestRequest::get()
            .uri("/api/urls/1")
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    #[actix_rt::test]
    async fn test_get_url_stats_endpoint() {
        let pool = setup_test_pool();
        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("statstest".to_string()),
            expires_in_hours: None,
        };
        let url = services::create_url(&pool, &request, 7, user.id).unwrap();

        services::record_click(&pool, url.id, Some("127.0.0.1"), None, None).unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::get()
            .uri(&format!("/api/urls/{}/stats", url.id))
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body.get("url").is_some());
        assert!(body.get("recent_clicks").is_some());
    }

    #[actix_rt::test]
    async fn test_delete_url_requires_auth() {
        let pool = setup_test_pool();
        let app = setup_test_app(pool).await;

        let req = test::TestRequest::delete()
            .uri("/api/urls/1")
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    // ========================================================================
    // New Redirect Handler Tests
    // ========================================================================

    #[actix_rt::test]
    async fn test_redirect_not_found() {
        let pool = setup_test_pool();
        let app = setup_test_app(pool).await;

        let req = test::TestRequest::get()
            .uri("/nonexistent_code")
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    #[actix_rt::test]
    async fn test_redirect_favicon_returns_404() {
        let pool = setup_test_pool();
        let app = setup_test_app(pool).await;

        let req = test::TestRequest::get()
            .uri("/favicon.ico")
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    #[actix_rt::test]
    async fn test_redirect_robots_txt_returns_404() {
        let pool = setup_test_pool();
        let app = setup_test_app(pool).await;

        let req = test::TestRequest::get()
            .uri("/robots.txt")
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    // ========================================================================
    // New Bulk Handler Tests
    // ========================================================================

    #[actix_rt::test]
    async fn test_bulk_delete_requires_auth() {
        let pool = setup_test_pool();
        let app = setup_test_app(pool).await;

        let req = test::TestRequest::delete()
            .uri("/api/urls/bulk")
            .set_json(serde_json::json!({ "ids": [1, 2, 3] }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    #[actix_rt::test]
    async fn test_bulk_create_with_invalid_url_format() {
        let pool = setup_test_pool();
        let (_, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::post()
            .uri("/api/urls/bulk")
            .insert_header(("X-API-Key", api_key))
            .set_json(serde_json::json!({
                "urls": [
                    { "url": "not-a-valid-url" }
                ]
            }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_rt::test]
    async fn test_bulk_delete_validates_limit() {
        let pool = setup_test_pool();
        let (_, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let app = setup_test_app(pool).await;

        let ids: Vec<i64> = (1..=101).collect();

        let req = test::TestRequest::delete()
            .uri("/api/urls/bulk")
            .insert_header(("X-API-Key", api_key))
            .set_json(serde_json::json!({ "ids": ids }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    // ========================================================================
    // New Tag Handler Tests
    // ========================================================================

    #[actix_rt::test]
    async fn test_remove_tag_from_url_endpoint() {
        let pool = setup_test_pool();
        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let tag = services::create_tag(&pool, "RemoveMe", user.id).unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("rmtag".to_string()),
            expires_in_hours: None,
        };
        let url = services::create_url(&pool, &request, 7, user.id).unwrap();
        services::add_tag_to_url(&pool, url.id, tag.id, user.id).unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::delete()
            .uri(&format!("/api/urls/{}/tags/{}", url.id, tag.id))
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_rt::test]
    async fn test_tag_ownership_isolation() {
        let pool = setup_test_pool();
        let (user1, _) = services::register_user(&pool, "user1@example.com").unwrap();
        let (_, api_key2) = services::register_user(&pool, "user2@example.com").unwrap();

        let tag = services::create_tag(&pool, "Private", user1.id).unwrap();

        let app = setup_test_app(pool).await;

        // User2 tries to delete user1's tag
        let req = test::TestRequest::delete()
            .uri(&format!("/api/tags/{}", tag.id))
            .insert_header(("X-API-Key", api_key2))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    #[actix_rt::test]
    async fn test_add_tag_to_url_not_found() {
        let pool = setup_test_pool();
        let (_, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let app = setup_test_app(pool).await;

        let req = test::TestRequest::post()
            .uri("/api/urls/99999/tags")
            .insert_header(("X-API-Key", api_key))
            .set_json(serde_json::json!({ "tag_id": 99999 }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    // ========================================================================
    // New Analytics Handler Tests
    // ========================================================================

    #[actix_rt::test]
    async fn test_analytics_respects_ownership() {
        let pool = setup_test_pool();
        let (user1, _) = services::register_user(&pool, "user1@example.com").unwrap();
        let (_, api_key2) = services::register_user(&pool, "user2@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("owned_analytics".to_string()),
            expires_in_hours: None,
        };
        let url = services::create_url(&pool, &request, 7, user1.id).unwrap();

        let app = setup_test_app(pool).await;

        // User2 tries to access user1's analytics
        let endpoints = [
            format!("/api/urls/{}/analytics/timeline", url.id),
            format!("/api/urls/{}/analytics/referrers", url.id),
            format!("/api/urls/{}/analytics/browsers", url.id),
            format!("/api/urls/{}/analytics/devices", url.id),
        ];

        for endpoint in &endpoints {
            let req = test::TestRequest::get()
                .uri(endpoint)
                .insert_header(("X-API-Key", api_key2.clone()))
                .to_request();

            let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
            assert_eq!(resp.status(), 404, "Endpoint {} should deny access to non-owner", endpoint);
        }
    }
}
