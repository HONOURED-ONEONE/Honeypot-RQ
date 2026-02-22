// 03_COMPOSE_TILES - Compose tiles & dashboard JSON for Value Dashboard, normalize KPIs & thresholds

function pct(v) {
  return Math.round((v || 0) * 10) / 10
}
function pickColor(kpi, warn, crit) {
  if (crit !== undefined && kpi <= crit) return "critical"
  if (warn !== undefined && kpi <= warn) return "warning"
  return "ok"
}

;(async () => {
  const norm = typeof getContext === "function" ? getContext("value_dashboard.normalized") : undefined
  if (!norm || !norm.intake) {
    setContext("value_dashboard.tiles", [])
    setContext("value_dashboard.dashboard_payload", {})
    console.error(JSON.stringify({ step: "03_COMPOSE_TILES", result: "fail", ts: new Date().toISOString(), reason: "normalized missing" }))
    process.exit(1)
  }

  const env = process.env
  // Parse thresholds
  const P95_FINALIZE_WARN = parseFloat(env.P95_FINALIZE_WARN) || 5
  const P95_FINALIZE_CRIT = parseFloat(env.P95_FINALIZE_CRIT) || 10
  const CB_SUCCESS_WARN = parseFloat(env.CB_SUCCESS_WARN) || 99.9
  const CB_SUCCESS_CRIT = parseFloat(env.CB_SUCCESS_CRIT) || 99.0
  const CB_P95_WARN = parseFloat(env.CB_P95_WARN) || 3
  const CB_P95_CRIT = parseFloat(env.CB_P95_CRIT) || 5
  const REFRESH_SECONDS = parseInt(env.REFRESH_SECONDS, 10) || 60

  // TILES ARRAY
  const tiles = [
    // 1) Intake Health
    {
      id: "tile_intake_health",
      type: "status",
      refreshSeconds: REFRESH_SECONDS,
      title: "Intake Health",
      status: (norm.intake.status && norm.intake.status.current) || "unknown",
      spark: (norm.intake.status && norm.intake.status.trend_60m) || []
    },
    // 2) Cases & Confirmed Rate
    {
      id: "tile_cases_confirmed",
      type: "kpi",
      refreshSeconds: REFRESH_SECONDS,
      title: "Cases & Confirmed Rate",
      value: (norm.cases.cases && norm.cases.cases.total_7d) || 0,
      pctConfirmed: pct(norm.cases.cases && norm.cases.cases.confirmed_rate),
      trend: (norm.cases.cases && norm.cases.cases.daily_trend_14d) || []
    },
    // 3) Time to Final Report
    {
      id: "tile_finalize_latency",
      type: "latency",
      refreshSeconds: REFRESH_SECONDS,
      title: "Time to Final Report",
      p50: (norm.finalize.finalize_latency && norm.finalize.finalize_latency.p50_seconds) || 0,
      p95: (norm.finalize.finalize_latency && norm.finalize.finalize_latency.p95_seconds) || 0,
      color: pickColor(norm.finalize.finalize_latency && norm.finalize.finalize_latency.p95_seconds, P95_FINALIZE_WARN, P95_FINALIZE_CRIT)
    },
    // 4) Callback Delivery SLO
    {
      id: "tile_callback_slo",
      type: "callback",
      refreshSeconds: REFRESH_SECONDS,
      title: "Callback Delivery",
      pct: pct(norm.callback.delivery && norm.callback.delivery.success_pct_15m),
      p95: (norm.callback.delivery && norm.callback.delivery.p95_latency_seconds_15m) || 0,
      color: pickColor(pct(norm.callback.delivery && norm.callback.delivery.success_pct_15m), CB_SUCCESS_WARN, CB_SUCCESS_CRIT)
    },
    // 5) Evidence Quality
    {
      id: "tile_evidence_quality",
      type: "kpi",
      refreshSeconds: REFRESH_SECONDS,
      title: "Evidence Quality",
      avgIOC: (norm.cases.evidence && norm.cases.evidence.avg_distinct_ioc_categories_7d) || 0,
      trend: (norm.cases.evidence && norm.cases.evidence.daily_avg_ioc_categories_14d) || []
    },
    // 6) Evidence Actions
    {
      id: "tile_evidence_actions",
      type: "actions",
      refreshSeconds: REFRESH_SECONDS,
      title: "Evidence Actions",
      exports: (norm.evidence.counts && norm.evidence.counts.exports_7d) || 0,
      forwards: (norm.evidence.counts && norm.evidence.counts.forwards_7d) || 0
    }
  ]
  // Optionally Tile 7: Rich text/crosslink
  tiles.push({ id: "tile_ops_note", type: "richtext", title: "More: Incidents on Control Dashboard", markdown: "[View Control Dashboard for full incident analytics.](#control-dashboard)", refreshSeconds: REFRESH_SECONDS })

  // Final dashboard payload
  const dashId = env.DASHBOARD_ID,
    dashName = env.DASHBOARD_NAME,
    dashDesc = env.DASHBOARD_DESC
  const payload = {
    id: dashId,
    name: dashName,
    description: dashDesc,
    layout: { grid: { columns: 12, rowHeight: 90 } },
    tiles
  }
  setContext("value_dashboard.tiles", tiles)
  setContext("value_dashboard.dashboard_payload", payload)
  // Log preview summary with major KPIs per tile
  console.log(JSON.stringify({ step: "03_COMPOSE_TILES", ts: new Date().toISOString(), dashId, tiles: tiles.map(t => ({ id: t.id, title: t.title, value: t.value || t.pct || t.status || null })) }))
})()
