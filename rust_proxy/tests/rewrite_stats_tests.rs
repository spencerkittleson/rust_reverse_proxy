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

use clap::Parser;
use rust_proxy::http_rewrite::RewritePolicy;
use rust_proxy::Args;

#[test]
fn fallback_is_off_by_default() {
    // The safe posture must be the one you get without thinking about it.
    let args = Args::try_parse_from(["rust_proxy"]).unwrap();
    assert!(!args.rewrite_fallback);
    assert_eq!(args.rewrite_policy(), RewritePolicy::FailClosed);
}

#[test]
fn fallback_flag_opts_into_leaking() {
    let args = Args::try_parse_from(["rust_proxy", "--rewrite-fallback"]).unwrap();
    assert!(args.rewrite_fallback);
    assert_eq!(args.rewrite_policy(), RewritePolicy::Fallback);
}

#[test]
fn fallback_flag_composes_with_existing_flags() {
    let args = Args::try_parse_from([
        "rust_proxy",
        "--host",
        "127.0.0.1",
        "--port",
        "9999",
        "--rewrite-fallback",
    ])
    .unwrap();
    assert_eq!(args.host, "127.0.0.1");
    assert_eq!(args.port, 9999);
    assert!(args.rewrite_fallback);
}

#[test]
fn help_text_names_the_privacy_cost() {
    // A flag whose downside is discoverable only by reading the design doc is a trap.
    let help = Args::try_parse_from(["rust_proxy", "--help"])
        .unwrap_err()
        .to_string();
    assert!(help.contains("--rewrite-fallback"));
    let lowered = help.to_lowercase();
    assert!(
        lowered.contains("leak"),
        "help must state the leak: {help}"
    );
}
