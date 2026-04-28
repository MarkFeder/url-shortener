//! Click log queries for analytics.

pub struct ClickLogs;

impl ClickLogs {
    pub const INSERT: &'static str =
        "INSERT INTO click_logs (url_id, ip_address, user_agent, referer, browser, browser_version, os, device_type, referer_domain) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";

    pub const SELECT_BY_URL_ID: &'static str = "
        SELECT id, url_id, clicked_at, ip_address, user_agent, referer,
               browser, browser_version, os, device_type, referer_domain
        FROM click_logs
        WHERE url_id = ?1
        ORDER BY clicked_at DESC
        LIMIT ?2";

    pub const TIMELINE_HOURLY: &'static str = "
        SELECT strftime('%Y-%m-%d %H:00:00', clicked_at) AS bucket, COUNT(*) AS count
        FROM click_logs
        WHERE url_id = ?1
        GROUP BY bucket
        ORDER BY bucket DESC
        LIMIT ?2";

    pub const TIMELINE_DAILY: &'static str = "
        SELECT strftime('%Y-%m-%d', clicked_at) AS bucket, COUNT(*) AS count
        FROM click_logs
        WHERE url_id = ?1
        GROUP BY bucket
        ORDER BY bucket DESC
        LIMIT ?2";

    pub const TIMELINE_WEEKLY: &'static str = "
        SELECT strftime('%Y-W%W', clicked_at) AS bucket, COUNT(*) AS count
        FROM click_logs
        WHERE url_id = ?1
        GROUP BY bucket
        ORDER BY bucket DESC
        LIMIT ?2";

    pub const TOP_REFERRERS: &'static str = "
        SELECT COALESCE(referer_domain, 'direct') AS domain, COUNT(*) AS count
        FROM click_logs
        WHERE url_id = ?1
        GROUP BY domain
        ORDER BY count DESC
        LIMIT ?2";

    pub const BROWSER_BREAKDOWN: &'static str = "
        SELECT COALESCE(browser, 'unknown') AS name, COUNT(*) AS count
        FROM click_logs
        WHERE url_id = ?1
        GROUP BY name
        ORDER BY count DESC
        LIMIT ?2";

    pub const DEVICE_BREAKDOWN: &'static str = "
        SELECT COALESCE(device_type, 'unknown') AS name, COUNT(*) AS count
        FROM click_logs
        WHERE url_id = ?1
        GROUP BY name
        ORDER BY count DESC
        LIMIT ?2";

    pub const DELETE_BEFORE: &'static str =
        "DELETE FROM click_logs WHERE clicked_at < ?1";
}
