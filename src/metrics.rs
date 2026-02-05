//! Prometheus metrics module for the URL shortener.
//!
//! Defines custom business metrics for monitoring cache performance,
//! redirect counts, URL creations, and API key validations.

use prometheus::{Counter, CounterVec, Opts, Registry};

/// Application metrics for Prometheus monitoring
#[derive(Clone)]
pub struct AppMetrics {
    /// Cache hit counter with cache_type label (url, api_key)
    pub cache_hits_total: CounterVec,
    /// Cache miss counter with cache_type label (url, api_key)
    pub cache_misses_total: CounterVec,
    /// Total URL redirects performed
    pub redirects_total: Counter,
    /// Total URLs created
    pub urls_created_total: Counter,
    /// API key validation attempts with result label (success, invalid)
    pub api_key_validations_total: CounterVec,
}

impl AppMetrics {
    /// Create and register all custom metrics with the given Prometheus registry
    pub fn new(registry: &Registry) -> Result<Self, prometheus::Error> {
        let cache_hits_total = CounterVec::new(
            Opts::new("cache_hits_total", "Total cache hits")
                .namespace("url_shortener"),
            &["cache_type"],
        )?;
        registry.register(Box::new(cache_hits_total.clone()))?;

        let cache_misses_total = CounterVec::new(
            Opts::new("cache_misses_total", "Total cache misses")
                .namespace("url_shortener"),
            &["cache_type"],
        )?;
        registry.register(Box::new(cache_misses_total.clone()))?;

        let redirects_total = Counter::with_opts(
            Opts::new("redirects_total", "Total URL redirects performed")
                .namespace("url_shortener"),
        )?;
        registry.register(Box::new(redirects_total.clone()))?;

        let urls_created_total = Counter::with_opts(
            Opts::new("urls_created_total", "Total URLs created")
                .namespace("url_shortener"),
        )?;
        registry.register(Box::new(urls_created_total.clone()))?;

        let api_key_validations_total = CounterVec::new(
            Opts::new("api_key_validations_total", "Total API key validation attempts")
                .namespace("url_shortener"),
            &["result"],
        )?;
        registry.register(Box::new(api_key_validations_total.clone()))?;

        Ok(Self {
            cache_hits_total,
            cache_misses_total,
            redirects_total,
            urls_created_total,
            api_key_validations_total,
        })
    }

    /// Record a cache hit for the given cache type
    pub fn record_cache_hit(&self, cache_type: &str) {
        self.cache_hits_total.with_label_values(&[cache_type]).inc();
    }

    /// Record a cache miss for the given cache type
    pub fn record_cache_miss(&self, cache_type: &str) {
        self.cache_misses_total.with_label_values(&[cache_type]).inc();
    }

    /// Record a URL redirect
    pub fn record_redirect(&self) {
        self.redirects_total.inc();
    }

    /// Record a URL creation
    pub fn record_url_created(&self) {
        self.urls_created_total.inc();
    }

    /// Record an API key validation attempt
    pub fn record_api_key_validation(&self, result: &str) {
        self.api_key_validations_total.with_label_values(&[result]).inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let registry = Registry::new();
        let metrics = AppMetrics::new(&registry).unwrap();

        // Verify metrics can be incremented without error
        metrics.record_cache_hit("url");
        metrics.record_cache_hit("api_key");
        metrics.record_cache_miss("url");
        metrics.record_cache_miss("api_key");
        metrics.record_redirect();
        metrics.record_url_created();
        metrics.record_api_key_validation("success");
        metrics.record_api_key_validation("invalid");
    }

    #[test]
    fn test_metrics_values() {
        let registry = Registry::new();
        let metrics = AppMetrics::new(&registry).unwrap();

        // Record some metrics
        metrics.record_cache_hit("url");
        metrics.record_cache_hit("url");
        metrics.record_cache_miss("url");
        metrics.record_redirect();
        metrics.record_redirect();
        metrics.record_redirect();

        // Verify values
        assert_eq!(
            metrics.cache_hits_total.with_label_values(&["url"]).get() as u64,
            2
        );
        assert_eq!(
            metrics.cache_misses_total.with_label_values(&["url"]).get() as u64,
            1
        );
        assert_eq!(metrics.redirects_total.get() as u64, 3);
    }
}
