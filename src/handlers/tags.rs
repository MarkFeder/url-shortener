//! Tag endpoint handlers: tag CRUD and URL-tag associations.

use actix_web::{delete, get, post, web, HttpResponse};
use validator::Validate;

use crate::auth::AuthenticatedUser;
use crate::config::Config;
use crate::db::DbPool;
use crate::errors::AppError;
use crate::models::{
    AddTagToUrlRequest, CreateTagRequest, MessageResponse, TagListResponse, TagResponse,
    UrlWithTagsResponse, UrlsByTagResponse,
};
use crate::services;

/// Create a new tag
#[post("/tags")]
pub(super) async fn create_tag(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    body: web::Json<CreateTagRequest>,
) -> Result<HttpResponse, AppError> {
    body.validate()
        .map_err(|e| AppError::ValidationError(format!("Invalid input: {}", e)))?;

    let tag = services::create_tag(&pool, &body.name, user.user_id)?;

    let response = TagResponse::from_tag(&tag);
    Ok(HttpResponse::Created().json(response))
}

/// List all tags for the authenticated user
#[get("/tags")]
pub(super) async fn list_tags(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
) -> Result<HttpResponse, AppError> {
    let tags = services::list_tags(&pool, user.user_id)?;

    let tag_responses: Vec<TagResponse> = tags.iter().map(TagResponse::from_tag).collect();

    let response = TagListResponse {
        tags: tag_responses,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Delete a tag
#[delete("/tags/{id}")]
pub(super) async fn delete_tag(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    path: web::Path<i64>,
) -> Result<HttpResponse, AppError> {
    let tag_id = path.into_inner();
    services::delete_tag(&pool, tag_id, user.user_id)?;

    Ok(HttpResponse::Ok().json(MessageResponse::new("Tag deleted successfully")))
}

/// Add a tag to a URL
#[post("/urls/{id}/tags")]
pub(super) async fn add_tag_to_url(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    path: web::Path<i64>,
    body: web::Json<AddTagToUrlRequest>,
) -> Result<HttpResponse, AppError> {
    let url_id = path.into_inner();
    services::add_tag_to_url(&pool, url_id, body.tag_id, user.user_id)?;

    Ok(HttpResponse::Created().json(MessageResponse::new("Tag added to URL successfully")))
}

/// Remove a tag from a URL
#[delete("/urls/{id}/tags/{tag_id}")]
pub(super) async fn remove_tag_from_url(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    path: web::Path<(i64, i64)>,
) -> Result<HttpResponse, AppError> {
    let (url_id, tag_id) = path.into_inner();
    services::remove_tag_from_url(&pool, url_id, tag_id, user.user_id)?;

    Ok(HttpResponse::Ok().json(MessageResponse::new("Tag removed from URL successfully")))
}

/// Get all URLs with a specific tag
#[get("/tags/{id}/urls")]
pub(super) async fn get_urls_by_tag(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    config: web::Data<Config>,
    path: web::Path<i64>,
) -> Result<HttpResponse, AppError> {
    let tag_id = path.into_inner();

    let urls_with_tags = services::get_urls_by_tag_with_tags(&pool, tag_id, user.user_id)?;

    let url_responses: Vec<UrlWithTagsResponse> = urls_with_tags
        .into_iter()
        .map(|(url, tags)| {
            let tag_responses: Vec<TagResponse> = tags.iter().map(TagResponse::from_tag).collect();
            UrlWithTagsResponse {
                id: url.id,
                short_code: url.short_code.clone(),
                short_url: format!("{}/{}", config.base_url, url.short_code),
                original_url: url.original_url,
                clicks: url.clicks,
                created_at: url.created_at,
                updated_at: url.updated_at,
                expires_at: url.expires_at,
                tags: tag_responses,
            }
        })
        .collect();

    let response = UrlsByTagResponse {
        urls: url_responses,
    };

    Ok(HttpResponse::Ok().json(response))
}
