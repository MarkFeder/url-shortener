//! Analytics query parameters and breakdown response DTOs.

use serde::{Deserialize, Serialize};

use crate::infra::constants::DEFAULT_ANALYTICS_PERIOD;

/// Query parameters for analytics timeline endpoint
#[derive(Debug, Clone, Deserialize)]
pub struct TimelineQuery {
    /// Period: "hourly", "daily", or "weekly"
    pub period: Option<String>,
    /// Maximum number of buckets to return
    pub limit: Option<u32>,
}

impl Default for TimelineQuery {
    fn default() -> Self {
        Self {
            period: Some(DEFAULT_ANALYTICS_PERIOD.to_string()),
            limit: Some(30),
        }
    }
}

/// Query parameters for breakdown analytics endpoints
#[derive(Debug, Clone, Deserialize)]
pub struct BreakdownQuery {
    /// Maximum number of entries to return
    pub limit: Option<u32>,
}

/// A single time bucket in a timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineBucket {
    /// The time bucket label
    pub bucket: String,
    /// Number of clicks in this bucket
    pub count: i64,
}

/// Response for the timeline analytics endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineResponse {
    /// The period used (hourly, daily, weekly)
    pub period: String,
    /// The timeline data
    pub data: Vec<TimelineBucket>,
}

/// A single entry in a breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakdownEntry {
    /// The name/label of this entry
    pub name: String,
    /// The count for this entry
    pub count: i64,
}

/// Response for the referrer breakdown endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferrerBreakdownResponse {
    /// Referrer breakdown data
    pub data: Vec<BreakdownEntry>,
}

/// Response for the browser breakdown endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserBreakdownResponse {
    /// Browser breakdown data
    pub data: Vec<BreakdownEntry>,
}

/// Response for the device breakdown endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceBreakdownResponse {
    /// Device breakdown data
    pub data: Vec<BreakdownEntry>,
}
