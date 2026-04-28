//! QR code query parameters.

use serde::Deserialize;

/// Query parameters for QR code generation
#[derive(Debug, Clone, Deserialize)]
pub struct QrCodeQuery {
    /// Output format: "png" (default) or "svg"
    pub format: Option<String>,
    /// Size in pixels (default: 256, min: 64, max: 1024)
    pub size: Option<u32>,
}
