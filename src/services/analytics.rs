//! Click tracking and analytics aggregation services.

use chrono::{Duration, Utc};
use rusqlite::params;

use super::helpers::map_click_log_row;
use crate::db::{get_conn, DbPool};
use crate::errors::AppError;
use crate::models::{BreakdownEntry, ClickLog, TimelineBucket};
use crate::queries::{ClickLogs, Urls};

/// Parsed user-agent information
pub struct ParsedUserAgent {
    pub browser: Option<String>,
    pub browser_version: Option<String>,
    pub os: Option<String>,
    pub device_type: Option<String>,
}

/// Parse a user-agent string into structured components
pub fn parse_user_agent(ua: &str) -> ParsedUserAgent {
    if ua.is_empty() {
        return ParsedUserAgent {
            browser: None,
            browser_version: None,
            os: None,
            device_type: None,
        };
    }

    let parser = woothee::parser::Parser::new();
    match parser.parse(ua) {
        Some(result) => {
            let device_type = match result.category {
                "pc" => "desktop",
                "smartphone" => "mobile",
                "mobilephone" => "mobile",
                "crawler" => "bot",
                _ => "other",
            };

            ParsedUserAgent {
                browser: if result.name != "UNKNOWN" {
                    Some(result.name.to_string())
                } else {
                    None
                },
                browser_version: if result.version != "UNKNOWN" {
                    Some(result.version.to_string())
                } else {
                    None
                },
                os: if result.os != "UNKNOWN" {
                    Some(result.os.to_string())
                } else {
                    None
                },
                device_type: Some(device_type.to_string()),
            }
        }
        None => ParsedUserAgent {
            browser: None,
            browser_version: None,
            os: None,
            device_type: None,
        },
    }
}

/// Extract the domain from a referer URL
pub fn extract_referer_domain(referer: &str) -> Option<String> {
    url::Url::parse(referer)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
}

/// Increment click count for a URL (always called on redirect)
pub fn increment_clicks(pool: &DbPool, url_id: i64) -> Result<(), AppError> {
    let conn = get_conn(pool)?;
    conn.execute(Urls::INCREMENT_CLICKS, params![url_id])?;
    Ok(())
}

/// Log click details (called only when click logging is enabled)
pub fn record_click(
    pool: &DbPool,
    url_id: i64,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    referer: Option<&str>,
) -> Result<(), AppError> {
    let conn = get_conn(pool)?;

    let parsed_ua = user_agent
        .map(parse_user_agent)
        .unwrap_or(ParsedUserAgent {
            browser: None,
            browser_version: None,
            os: None,
            device_type: None,
        });

    let referer_domain = referer.and_then(extract_referer_domain);

    conn.execute(
        ClickLogs::INSERT,
        params![
            url_id,
            ip_address,
            user_agent,
            referer,
            parsed_ua.browser,
            parsed_ua.browser_version,
            parsed_ua.os,
            parsed_ua.device_type,
            referer_domain
        ],
    )?;

    Ok(())
}

/// Get click logs for a URL
pub fn get_click_logs(pool: &DbPool, url_id: i64, limit: u32) -> Result<Vec<ClickLog>, AppError> {
    let conn = get_conn(pool)?;
    let mut stmt = conn.prepare(ClickLogs::SELECT_BY_URL_ID)?;

    let logs = stmt
        .query_map(params![url_id, limit], map_click_log_row)?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(logs)
}

/// Get click timeline for a URL
pub fn get_click_timeline(
    pool: &DbPool,
    url_id: i64,
    period: &str,
    limit: u32,
) -> Result<Vec<TimelineBucket>, AppError> {
    let conn = get_conn(pool)?;

    let query = match period {
        "hourly" => ClickLogs::TIMELINE_HOURLY,
        "weekly" => ClickLogs::TIMELINE_WEEKLY,
        _ => ClickLogs::TIMELINE_DAILY,
    };

    let mut stmt = conn.prepare(query)?;
    let buckets = stmt
        .query_map(params![url_id, limit], |row| {
            Ok(TimelineBucket {
                bucket: row.get(0)?,
                count: row.get(1)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(buckets)
}

/// Get referrer breakdown for a URL
pub fn get_referrer_breakdown(
    pool: &DbPool,
    url_id: i64,
    limit: u32,
) -> Result<Vec<BreakdownEntry>, AppError> {
    let conn = get_conn(pool)?;
    let mut stmt = conn.prepare(ClickLogs::TOP_REFERRERS)?;

    let entries = stmt
        .query_map(params![url_id, limit], |row| {
            Ok(BreakdownEntry {
                name: row.get(0)?,
                count: row.get(1)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(entries)
}

/// Get browser breakdown for a URL
pub fn get_browser_breakdown(
    pool: &DbPool,
    url_id: i64,
    limit: u32,
) -> Result<Vec<BreakdownEntry>, AppError> {
    let conn = get_conn(pool)?;
    let mut stmt = conn.prepare(ClickLogs::BROWSER_BREAKDOWN)?;

    let entries = stmt
        .query_map(params![url_id, limit], |row| {
            Ok(BreakdownEntry {
                name: row.get(0)?,
                count: row.get(1)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(entries)
}

/// Get device breakdown for a URL
pub fn get_device_breakdown(
    pool: &DbPool,
    url_id: i64,
    limit: u32,
) -> Result<Vec<BreakdownEntry>, AppError> {
    let conn = get_conn(pool)?;
    let mut stmt = conn.prepare(ClickLogs::DEVICE_BREAKDOWN)?;

    let entries = stmt
        .query_map(params![url_id, limit], |row| {
            Ok(BreakdownEntry {
                name: row.get(0)?,
                count: row.get(1)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(entries)
}

/// Cleanup old click logs based on retention period
pub fn cleanup_old_click_logs(pool: &DbPool, retention_days: u64) -> Result<usize, AppError> {
    let conn = get_conn(pool)?;
    let cutoff = (Utc::now() - Duration::days(retention_days as i64))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();

    let deleted = conn.execute(ClickLogs::DELETE_BEFORE, params![cutoff])?;
    if deleted > 0 {
        log::info!(
            "Cleaned up {} click log entries older than {} days",
            deleted,
            retention_days
        );
    }
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::get_conn;
    use crate::models::CreateUrlRequest;
    use crate::services::{create_url, register_user};
    use crate::test_utils::setup_test_db;

    #[test]
    fn test_parse_user_agent_chrome() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        let parsed = parse_user_agent(ua);
        assert_eq!(parsed.browser.as_deref(), Some("Chrome"));
        assert!(parsed.browser_version.is_some());
        assert!(parsed.os.is_some());
        assert_eq!(parsed.device_type.as_deref(), Some("desktop"));
    }

    #[test]
    fn test_parse_user_agent_safari_mobile() {
        let ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";
        let parsed = parse_user_agent(ua);
        assert!(parsed.browser.is_some());
        assert_eq!(parsed.device_type.as_deref(), Some("mobile"));
    }

    #[test]
    fn test_parse_user_agent_googlebot() {
        let ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
        let parsed = parse_user_agent(ua);
        assert_eq!(parsed.device_type.as_deref(), Some("bot"));
    }

    #[test]
    fn test_parse_user_agent_empty() {
        let parsed = parse_user_agent("");
        assert!(parsed.browser.is_none());
        assert!(parsed.browser_version.is_none());
        assert!(parsed.os.is_none());
        assert!(parsed.device_type.is_none());
    }

    #[test]
    fn test_extract_referer_domain() {
        assert_eq!(
            extract_referer_domain("https://www.google.com/search?q=test"),
            Some("www.google.com".to_string())
        );
        assert_eq!(
            extract_referer_domain("https://twitter.com/user/status/123"),
            Some("twitter.com".to_string())
        );
        assert_eq!(extract_referer_domain("not-a-url"), None);
        assert_eq!(extract_referer_domain(""), None);
    }

    #[test]
    fn test_click_tracking() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("clicks".to_string()),
            expires_in_hours: None,
        };

        let url = create_url(&pool, &request, 7, user.id).unwrap();
        assert_eq!(url.clicks, 0);

        increment_clicks(&pool, url.id).unwrap();
        record_click(&pool, url.id, Some("127.0.0.1"), None, None).unwrap();

        let updated = crate::services::get_url_by_id(&pool, url.id, user.id).unwrap();
        assert_eq!(updated.clicks, 1);
    }

    #[test]
    fn test_increment_clicks() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("incr".to_string()),
            expires_in_hours: None,
        };

        let url = create_url(&pool, &request, 7, user.id).unwrap();
        assert_eq!(url.clicks, 0);

        increment_clicks(&pool, url.id).unwrap();
        increment_clicks(&pool, url.id).unwrap();

        let updated = crate::services::get_url_by_id(&pool, url.id, user.id).unwrap();
        assert_eq!(updated.clicks, 2);
    }

    #[test]
    fn test_record_click_with_parsed_data() {
        let pool = setup_test_db();
        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("click_test".to_string()),
            expires_in_hours: None,
        };
        let url = create_url(&pool, &request, 7, user.id).unwrap();

        // Record a click with a Chrome user agent
        increment_clicks(&pool, url.id).unwrap();
        record_click(
            &pool,
            url.id,
            Some("127.0.0.1"),
            Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
            Some("https://www.google.com/search?q=test"),
        )
        .unwrap();

        let logs = get_click_logs(&pool, url.id, 10).unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].browser.as_deref(), Some("Chrome"));
        assert!(logs[0].browser_version.is_some());
        assert!(logs[0].os.is_some());
        assert_eq!(logs[0].device_type.as_deref(), Some("desktop"));
        assert_eq!(logs[0].referer_domain.as_deref(), Some("www.google.com"));
    }

    #[test]
    fn test_click_timeline() {
        let pool = setup_test_db();
        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("timeline_test".to_string()),
            expires_in_hours: None,
        };
        let url = create_url(&pool, &request, 7, user.id).unwrap();

        // Record a few clicks
        for _ in 0..5 {
            increment_clicks(&pool, url.id).unwrap();
            record_click(&pool, url.id, Some("127.0.0.1"), None, None).unwrap();
        }

        let timeline = get_click_timeline(&pool, url.id, "daily", 30).unwrap();
        assert!(!timeline.is_empty());
        // All clicks are on the same day, so we should have one bucket
        assert_eq!(timeline.len(), 1);
        assert_eq!(timeline[0].count, 5);
    }

    #[test]
    fn test_referrer_breakdown() {
        let pool = setup_test_db();
        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("ref_test".to_string()),
            expires_in_hours: None,
        };
        let url = create_url(&pool, &request, 7, user.id).unwrap();

        // Record clicks with different referrers
        increment_clicks(&pool, url.id).unwrap();
        record_click(&pool, url.id, None, None, Some("https://google.com/search")).unwrap();
        increment_clicks(&pool, url.id).unwrap();
        record_click(&pool, url.id, None, None, Some("https://google.com/other")).unwrap();
        increment_clicks(&pool, url.id).unwrap();
        record_click(&pool, url.id, None, None, Some("https://twitter.com/post")).unwrap();
        increment_clicks(&pool, url.id).unwrap();
        record_click(&pool, url.id, None, None, None).unwrap();

        let referrers = get_referrer_breakdown(&pool, url.id, 20).unwrap();
        assert!(!referrers.is_empty());

        // google.com should have 2 clicks
        let google = referrers.iter().find(|r| r.name == "google.com");
        assert!(google.is_some());
        assert_eq!(google.unwrap().count, 2);
    }

    #[test]
    fn test_browser_breakdown() {
        let pool = setup_test_db();
        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("browser_test".to_string()),
            expires_in_hours: None,
        };
        let url = create_url(&pool, &request, 7, user.id).unwrap();

        let chrome_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        let firefox_ua = "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0";

        increment_clicks(&pool, url.id).unwrap();
        record_click(&pool, url.id, None, Some(chrome_ua), None).unwrap();
        increment_clicks(&pool, url.id).unwrap();
        record_click(&pool, url.id, None, Some(chrome_ua), None).unwrap();
        increment_clicks(&pool, url.id).unwrap();
        record_click(&pool, url.id, None, Some(firefox_ua), None).unwrap();

        let browsers = get_browser_breakdown(&pool, url.id, 20).unwrap();
        assert!(!browsers.is_empty());

        let chrome = browsers.iter().find(|b| b.name == "Chrome");
        assert!(chrome.is_some());
        assert_eq!(chrome.unwrap().count, 2);
    }

    #[test]
    fn test_device_breakdown() {
        let pool = setup_test_db();
        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("device_test".to_string()),
            expires_in_hours: None,
        };
        let url = create_url(&pool, &request, 7, user.id).unwrap();

        let desktop_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        let mobile_ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";

        increment_clicks(&pool, url.id).unwrap();
        record_click(&pool, url.id, None, Some(desktop_ua), None).unwrap();
        increment_clicks(&pool, url.id).unwrap();
        record_click(&pool, url.id, None, Some(desktop_ua), None).unwrap();
        increment_clicks(&pool, url.id).unwrap();
        record_click(&pool, url.id, None, Some(mobile_ua), None).unwrap();

        let devices = get_device_breakdown(&pool, url.id, 20).unwrap();
        assert!(!devices.is_empty());

        let desktop = devices.iter().find(|d| d.name == "desktop");
        assert!(desktop.is_some());
        assert_eq!(desktop.unwrap().count, 2);
    }

    #[test]
    fn test_cleanup_old_click_logs() {
        let pool = setup_test_db();
        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("cleanup_test".to_string()),
            expires_in_hours: None,
        };
        let url = create_url(&pool, &request, 7, user.id).unwrap();

        // Insert click logs with old timestamps directly
        let conn = get_conn(&pool).unwrap();
        for _ in 0..3 {
            conn.execute(
                "INSERT INTO click_logs (url_id, clicked_at) VALUES (?1, datetime('now', '-10 days'))",
                params![url.id],
            )
            .unwrap();
        }

        // Also increment click count to match
        conn.execute("UPDATE urls SET clicks = 3 WHERE id = ?1", params![url.id]).unwrap();

        let logs = get_click_logs(&pool, url.id, 50).unwrap();
        assert_eq!(logs.len(), 3);

        // Cleanup with retention_days = 5 should delete everything older than 5 days
        let deleted = cleanup_old_click_logs(&pool, 5).unwrap();
        assert_eq!(deleted, 3);

        let logs = get_click_logs(&pool, url.id, 50).unwrap();
        assert!(logs.is_empty());
    }

    #[test]
    fn test_metrics_record_redirect() {
        let registry = prometheus::Registry::new();
        let metrics = crate::metrics::AppMetrics::new(&registry).unwrap();

        assert_eq!(metrics.redirects_total.get() as u64, 0);

        metrics.record_redirect();
        assert_eq!(metrics.redirects_total.get() as u64, 1);

        metrics.record_redirect();
        metrics.record_redirect();
        assert_eq!(metrics.redirects_total.get() as u64, 3);
    }
}
