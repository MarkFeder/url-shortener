//! Analytics endpoint handlers: timeline, referrers, browsers, devices.

use actix_web::{get, web, HttpResponse};

use crate::auth::AuthenticatedUser;
use crate::constants::MAX_ANALYTICS_RESULTS;
use crate::db::DbPool;
use crate::errors::AppError;
use crate::models::{
    BreakdownQuery, BrowserBreakdownResponse, DeviceBreakdownResponse,
    ReferrerBreakdownResponse, TimelineQuery, TimelineResponse,
};
use crate::services;

/// Get click timeline for a URL
#[get("/urls/{id}/analytics/timeline")]
pub(super) async fn get_url_analytics_timeline(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    path: web::Path<i64>,
    query: web::Query<TimelineQuery>,
) -> Result<HttpResponse, AppError> {
    let id = path.into_inner();

    services::get_url_by_id(&pool, id, user.user_id)?;

    let period = query.period.as_deref().unwrap_or("daily");
    if !["hourly", "daily", "weekly"].contains(&period) {
        return Err(AppError::ValidationError(
            "Invalid period. Must be one of: hourly, daily, weekly".into(),
        ));
    }

    let limit = query.limit.unwrap_or(30).min(MAX_ANALYTICS_RESULTS);

    let data = services::get_click_timeline(&pool, id, period, limit)?;

    let response = TimelineResponse {
        period: period.to_string(),
        data,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Get referrer breakdown for a URL
#[get("/urls/{id}/analytics/referrers")]
pub(super) async fn get_url_analytics_referrers(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    path: web::Path<i64>,
    query: web::Query<BreakdownQuery>,
) -> Result<HttpResponse, AppError> {
    let id = path.into_inner();
    services::get_url_by_id(&pool, id, user.user_id)?;

    let limit = query.limit.unwrap_or(20).min(MAX_ANALYTICS_RESULTS);
    let data = services::get_referrer_breakdown(&pool, id, limit)?;

    Ok(HttpResponse::Ok().json(ReferrerBreakdownResponse { data }))
}

/// Get browser breakdown for a URL
#[get("/urls/{id}/analytics/browsers")]
pub(super) async fn get_url_analytics_browsers(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    path: web::Path<i64>,
    query: web::Query<BreakdownQuery>,
) -> Result<HttpResponse, AppError> {
    let id = path.into_inner();
    services::get_url_by_id(&pool, id, user.user_id)?;

    let limit = query.limit.unwrap_or(20).min(MAX_ANALYTICS_RESULTS);
    let data = services::get_browser_breakdown(&pool, id, limit)?;

    Ok(HttpResponse::Ok().json(BrowserBreakdownResponse { data }))
}

/// Get device breakdown for a URL
#[get("/urls/{id}/analytics/devices")]
pub(super) async fn get_url_analytics_devices(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    path: web::Path<i64>,
    query: web::Query<BreakdownQuery>,
) -> Result<HttpResponse, AppError> {
    let id = path.into_inner();
    services::get_url_by_id(&pool, id, user.user_id)?;

    let limit = query.limit.unwrap_or(20).min(MAX_ANALYTICS_RESULTS);
    let data = services::get_device_breakdown(&pool, id, limit)?;

    Ok(HttpResponse::Ok().json(DeviceBreakdownResponse { data }))
}
