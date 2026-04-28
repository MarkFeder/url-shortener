//! Data models and DTOs (Data Transfer Objects) for the URL shortener.
//!
//! Organized by domain. Database entities live in `db`, request/response
//! DTOs in their respective domain submodules, and shared response types
//! (errors, message wrappers) in `common`. Everything is re-exported here
//! so callers can keep using `crate::models::X`.

mod analytics;
mod auth;
mod bulk;
mod common;
mod db;
mod qr;
mod tag;
mod url;
mod validators;

pub use analytics::{
    BreakdownEntry, BreakdownQuery, BrowserBreakdownResponse, DeviceBreakdownResponse,
    ReferrerBreakdownResponse, TimelineBucket, TimelineQuery, TimelineResponse,
};
pub use auth::{
    ApiKeyListResponse, ApiKeyResponse, CreateApiKeyRequest, CreateApiKeyResponse,
    RegisterRequest, RegisterResponse,
};
pub use bulk::{
    BulkCreateItemResult, BulkCreateUrlItem, BulkCreateUrlRequest, BulkCreateUrlResponse,
    BulkDeleteItemResult, BulkDeleteUrlRequest, BulkDeleteUrlResponse, BulkItemError,
    BulkOperationStatus,
};
pub use common::{ErrorResponse, MessageResponse};
pub use db::{ApiKeyRecord, ClickLog, Tag, Url, User};
pub use qr::QrCodeQuery;
pub use tag::{
    AddTagToUrlRequest, CreateTagRequest, TagListResponse, TagResponse, UrlWithTagsResponse,
    UrlsByTagResponse,
};
pub use url::{
    CreateUrlRequest, CreateUrlResponse, ListUrlsQuery, SearchUrlsQuery, UpdateUrlRequest,
    UrlListResponse, UrlResponse,
};
