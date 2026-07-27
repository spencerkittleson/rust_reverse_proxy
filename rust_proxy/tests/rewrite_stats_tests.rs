use rust_proxy::http_rewrite::RewriteAnomaly;
use rust_proxy::{Ordering, ProxyStats};

#[test]
fn counters_start_at_zero() {
    let stats = ProxyStats::new();
    assert_eq!(stats.requests_sanitized.load(Ordering::Relaxed), 0);
    for a in RewriteAnomaly::ALL {
        assert_eq!(stats.rewrite_anomalies[a.index()].load(Ordering::Relaxed), 0);
    }
    assert_eq!(stats.rewrite_fallback_forwarded.load(Ordering::Relaxed), 0);
}

#[test]
fn sanitized_requests_accumulate() {
    let stats = ProxyStats::new();
    stats.record_sanitized(3);
    stats.record_sanitized(2);
    assert_eq!(stats.requests_sanitized.load(Ordering::Relaxed), 5);
}

#[test]
fn anomalies_are_counted_per_reason_not_as_one_total() {
    let stats = ProxyStats::new();
    stats.record_anomaly(RewriteAnomaly::HeadTooLarge, "api.example.com", false);
    stats.record_anomaly(RewriteAnomaly::HeadTooLarge, "other.example.com", false);
    stats.record_anomaly(RewriteAnomaly::FramingConflict, "legacy.internal", false);

    assert_eq!(
        stats.rewrite_anomalies[RewriteAnomaly::HeadTooLarge.index()].load(Ordering::Relaxed),
        2
    );
    assert_eq!(
        stats.rewrite_anomalies[RewriteAnomaly::FramingConflict.index()].load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        stats.rewrite_anomalies[RewriteAnomaly::Unparseable.index()].load(Ordering::Relaxed),
        0
    );
}

#[test]
fn last_offending_host_is_retained_per_reason() {
    let stats = ProxyStats::new();
    stats.record_anomaly(RewriteAnomaly::HeadTooLarge, "first.example", false);
    stats.record_anomaly(RewriteAnomaly::HeadTooLarge, "second.example", false);
    stats.record_anomaly(RewriteAnomaly::Unparseable, "other.example", false);

    assert_eq!(
        stats.last_anomaly_host(RewriteAnomaly::HeadTooLarge).as_deref(),
        Some("second.example")
    );
    assert_eq!(
        stats.last_anomaly_host(RewriteAnomaly::Unparseable).as_deref(),
        Some("other.example")
    );
    assert_eq!(
        stats.last_anomaly_host(RewriteAnomaly::FramingConflict),
        None
    );
}

#[test]
fn only_forwarded_anomalies_count_toward_the_leak_total() {
    // A fail-closed anomaly leaked nothing, so it must not inflate the banner.
    let stats = ProxyStats::new();
    stats.record_anomaly(RewriteAnomaly::HeadTooLarge, "a.example", true);
    stats.record_anomaly(RewriteAnomaly::FramingConflict, "b.example", false);
    assert_eq!(stats.rewrite_fallback_forwarded.load(Ordering::Relaxed), 1);
}

#[test]
fn log_stats_runs_with_and_without_anomalies() {
    // Smoke test: the report must not panic on the empty or populated path.
    let stats = ProxyStats::new();
    stats.log_stats();

    stats.record_sanitized(10);
    stats.record_anomaly(RewriteAnomaly::HeadTooLarge, "api.example.com", true);
    stats.set_fallback_active(true);
    stats.log_stats();
}
