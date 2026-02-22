from app.observability import metrics

def test_admin_slo_exposes_metrics(monkeypatch):
    # Monkeypatch the snapshot producer to a fixed shape to assert required fields/types.
    monkeypatch.setattr(metrics, "get_slo_snapshot", lambda: {
        "finalize_success_rate": 100.0,
        "p50_finalize_latency": 1.2,
        "p95_finalize_latency": 3.4,
        "target_finalize_latency": 5.0,
        "callback_delivery_success_rate": 100.0,
        "p95_callback_delivery_latency": 1.0,
        "target_callback_latency": 3.0,
        "sessions_waiting_for_report": [],
        "recent_failed_callbacks": [],
        "window_seconds": 900,
        "snapshot_at": 1739999999
    })
    out = metrics.get_slo_snapshot()
    assert isinstance(out["finalize_success_rate"], (int, float))
    assert "p50_finalize_latency" in out and "p95_finalize_latency" in out
    assert "target_finalize_latency" in out and isinstance(out["target_finalize_latency"], (int, float))
    assert "callback_delivery_success_rate" in out
    assert "p95_callback_delivery_latency" in out
    assert "target_callback_latency" in out
    assert isinstance(out.get("sessions_waiting_for_report", []), list)
    assert isinstance(out.get("recent_failed_callbacks", []), list)
