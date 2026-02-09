//! Redirect endpoint handler.

use actix_web::{get, web, HttpRequest, HttpResponse};

use crate::cache::AppCache;
use crate::config::Config;
use crate::db::DbPool;
use crate::errors::AppError;
use crate::metrics::AppMetrics;
use crate::services;

/// Redirect to the original URL
///
/// This is the main functionality - when someone visits /{short_code},
/// they get redirected to the original URL.
#[get("/{short_code}")]
pub(super) async fn redirect_to_url(
    pool: web::Data<DbPool>,
    cache: web::Data<AppCache>,
    config: web::Data<Config>,
    metrics: Option<web::Data<AppMetrics>>,
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    let short_code = path.into_inner();

    // Don't redirect for common paths
    if short_code == "favicon.ico" || short_code == "robots.txt" {
        return Err(AppError::NotFound("Resource not found".into()));
    }

    let url = services::get_url_by_code_cached_with_metrics(
        &pool,
        &cache,
        &short_code,
        metrics.as_ref().map(|m| m.as_ref()),
    )?;

    // Extract request metadata for analytics
    let ip_address = req
        .connection_info()
        .realip_remote_addr()
        .map(|s| s.to_string());

    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let referer = req
        .headers()
        .get("referer")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // Always increment click count
    let _ = services::increment_clicks(&pool, url.id);

    // Record detailed click log if logging is enabled
    if config.click_logging_enabled {
        let _ = services::record_click(
            &pool,
            url.id,
            ip_address.as_deref(),
            user_agent.as_deref(),
            referer.as_deref(),
        );
    }

    // Record redirect metric
    if let Some(ref m) = metrics {
        m.record_redirect();
    }

    log::info!(
        "Redirecting {} -> {} (clicks: {})",
        short_code,
        url.original_url,
        url.clicks + 1
    );

    // Return 301 Moved Permanently redirect
    Ok(HttpResponse::MovedPermanently()
        .append_header(("Location", url.original_url))
        .finish())
}
