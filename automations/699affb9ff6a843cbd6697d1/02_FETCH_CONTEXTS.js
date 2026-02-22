// 02_FETCH_CONTEXTS - Fetch & normalize five dashboard sources (context API, warn on missing)

function safeGet(name, def, warnList) {
  try {
    const v = typeof getContext === "function" ? getContext(name) : undefined
    if (typeof v === "undefined" || v === null) {
      warnList.push(`Missing ${name}`)
      return def
    }
    return v
  } catch (e) {
    warnList.push(`Error getting ${name}: ${e}`)
    return def
  }
}

;(async () => {
  const warnList = []
  const env = process.env
  const intake = safeGet(env.SRC_INTAKE, { status: { current: "unknown", trend_60m: [] } }, warnList)
  const cases = safeGet(env.SRC_CASE_EXEC, { cases: { total_7d: 0, confirmed_rate: 0, daily_trend_14d: [] }, evidence: { avg_distinct_ioc_categories_7d: 0, daily_avg_ioc_categories_14d: [] } }, warnList)
  const callback = safeGet(env.SRC_CB_SLO, { delivery: { success_pct_15m: 0, p95_latency_seconds_15m: 0 } }, warnList)
  const finalize = safeGet(env.SRC_FIN_SLO, { finalize_latency: { p50_seconds: 0, p95_seconds: 0 } }, warnList)
  const evidence = safeGet(env.SRC_EVID_AUD, { counts: { exports_7d: 0, forwards_7d: 0 } }, warnList)
  // Only error if ALL are totally missing
  if ([intake, cases, callback, finalize, evidence].every(v => v && Object.keys(v).length === 0)) {
    console.error(JSON.stringify({ step: "02_FETCH_CONTEXTS", ts: new Date().toISOString(), result: "fail", err: "All dashboard source contexts are missing" }))
    process.exit(1)
  }
  setContext("value_dashboard.normalized", { intake, cases, callback, finalize, evidence })
  setContext("value_dashboard.last_fetch_ts", new Date().toISOString())
  console.log(JSON.stringify({ step: "02_FETCH_CONTEXTS", ts: new Date().toISOString(), result: "ok", warnCount: warnList.length, warns: warnList }))
})()
