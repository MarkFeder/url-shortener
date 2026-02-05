//! QR code generation module.
//!
//! Provides functionality to generate QR codes for short URLs
//! in both PNG and SVG formats.

use image::{ImageBuffer, Luma};
use qrcode::QrCode;
use std::io::Cursor;

use crate::errors::AppError;

/// QR code output format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QrFormat {
    #[default]
    Png,
    Svg,
}

impl QrFormat {
    /// Parse format from string (case-insensitive)
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "svg" => QrFormat::Svg,
            _ => QrFormat::Png,
        }
    }

    /// Get the content type for HTTP response
    pub fn content_type(&self) -> &'static str {
        match self {
            QrFormat::Png => "image/png",
            QrFormat::Svg => "image/svg+xml",
        }
    }
}

/// QR code generation options
#[derive(Debug, Clone)]
pub struct QrOptions {
    /// Output format (PNG or SVG)
    pub format: QrFormat,
    /// Size of the QR code (width/height in pixels for PNG, or viewBox for SVG)
    pub size: u32,
}

impl Default for QrOptions {
    fn default() -> Self {
        Self {
            format: QrFormat::Png,
            size: 256,
        }
    }
}

/// Generate a QR code for the given URL
///
/// Returns the QR code as bytes in the specified format.
pub fn generate_qr_code(url: &str, options: &QrOptions) -> Result<Vec<u8>, AppError> {
    // Create QR code
    let code = QrCode::new(url.as_bytes()).map_err(|e| {
        AppError::InternalError(format!("Failed to generate QR code: {}", e))
    })?;

    match options.format {
        QrFormat::Png => generate_png(&code, options.size),
        QrFormat::Svg => generate_svg(&code, options.size),
    }
}

/// Generate QR code as PNG image
fn generate_png(code: &QrCode, size: u32) -> Result<Vec<u8>, AppError> {
    // Render QR code to image
    let image = code.render::<Luma<u8>>().min_dimensions(size, size).build();

    // Encode as PNG
    let mut buffer = Cursor::new(Vec::new());
    let img: ImageBuffer<Luma<u8>, Vec<u8>> = image;

    img.write_to(&mut buffer, image::ImageFormat::Png)
        .map_err(|e| AppError::InternalError(format!("Failed to encode PNG: {}", e)))?;

    Ok(buffer.into_inner())
}

/// Generate QR code as SVG
fn generate_svg(code: &QrCode, size: u32) -> Result<Vec<u8>, AppError> {
    let svg = code
        .render()
        .min_dimensions(size, size)
        .dark_color(qrcode::render::svg::Color("#000000"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build();

    Ok(svg.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qr_format_from_str() {
        assert_eq!(QrFormat::from_str("png"), QrFormat::Png);
        assert_eq!(QrFormat::from_str("PNG"), QrFormat::Png);
        assert_eq!(QrFormat::from_str("svg"), QrFormat::Svg);
        assert_eq!(QrFormat::from_str("SVG"), QrFormat::Svg);
        assert_eq!(QrFormat::from_str("unknown"), QrFormat::Png);
    }

    #[test]
    fn test_qr_format_content_type() {
        assert_eq!(QrFormat::Png.content_type(), "image/png");
        assert_eq!(QrFormat::Svg.content_type(), "image/svg+xml");
    }

    #[test]
    fn test_generate_qr_code_png() {
        let options = QrOptions {
            format: QrFormat::Png,
            size: 128,
        };

        let result = generate_qr_code("https://example.com/test", &options);
        assert!(result.is_ok());

        let bytes = result.unwrap();
        // PNG files start with magic bytes
        assert!(bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47]));
    }

    #[test]
    fn test_generate_qr_code_svg() {
        let options = QrOptions {
            format: QrFormat::Svg,
            size: 128,
        };

        let result = generate_qr_code("https://example.com/test", &options);
        assert!(result.is_ok());

        let bytes = result.unwrap();
        let svg_str = String::from_utf8(bytes).unwrap();
        // SVG should contain svg tag
        assert!(svg_str.contains("<svg"));
        assert!(svg_str.contains("</svg>"));
    }

    #[test]
    fn test_generate_qr_code_default_options() {
        let options = QrOptions::default();
        assert_eq!(options.format, QrFormat::Png);
        assert_eq!(options.size, 256);

        let result = generate_qr_code("https://example.com", &options);
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_qr_code_various_urls() {
        let options = QrOptions::default();

        // Short URL
        assert!(generate_qr_code("http://localhost:8080/abc123", &options).is_ok());

        // Long URL
        assert!(generate_qr_code(
            "https://example.com/very/long/path/with/many/segments?query=value&another=param",
            &options
        )
        .is_ok());

        // URL with special characters
        assert!(generate_qr_code("https://example.com/path?q=hello%20world", &options).is_ok());
    }

    #[test]
    fn test_generate_qr_code_different_sizes() {
        for size in [64, 128, 256, 512] {
            let options = QrOptions {
                format: QrFormat::Png,
                size,
            };

            let result = generate_qr_code("https://example.com", &options);
            assert!(result.is_ok(), "Failed for size {}", size);
        }
    }
}
