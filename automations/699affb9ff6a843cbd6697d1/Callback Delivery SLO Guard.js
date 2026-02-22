const axios = require("axios")

// Scheduled SLO monitoring, every 1 min; restricted to SRE/Ops role.
;(async () => {
  try {
    setContext("required_role", "Ops")
    // Use new Honeypot admin API endpoint and key
    const baseUrl = process.env.HONEYPOT_BASE_URL
    const adminKey = process.env.HONEYPOT_ADMIN_KEY
    if (!baseUrl || !adminKey) {
      setContext("callback_slo_status", { error: "Missing HONEYPOT_BASE_URL or HONEYPOT_ADMIN_KEY." })
      process.exit(1)
    }
    const headers = { "x-admin-key": adminKey }
    // Query SLO metrics
    let sloMetrics = null
    try {
      const sloResp = await axios.get(`${baseUrl}/admin/slo`, { headers, timeout: 15000 })
      sloMetrics = sloResp.data
    } catch (e) {
      setContext("callback_slo_status", { error: "Failed to query /admin/slo", detail: e.message })
      process.exit(1)
    }
    // Evaluate SLOs
    const { callback_delivery_success_rate, p95_callback_delivery_latency, target_callback_latency, recent_failed_callbacks } = sloMetrics || {}
    let slaBreached = false
    let breachDetails = {}
    if ((callback_delivery_success_rate !== undefined && callback_delivery_success_rate < 99.9) || (p95_callback_delivery_latency !== undefined && p95_callback_delivery_latency > target_callback_latency)) {
      slaBreached = true
      breachDetails = { callback_delivery_success_rate, p95_callback_delivery_latency, thresholds: { minSuccess: 99.9, maxLatency: target_callback_latency } }
    }
    let incidentCount = slaBreached ? 1 : 0
    setContext("callback_slo_metrics", {
      delivery: {
        success_pct_15m: callback_delivery_success_rate,
        p95_latency_seconds_15m: p95_callback_delivery_latency
      },
      timestamp: new Date().toISOString()
    })
    if (slaBreached) {
      // Attach failed session artifacts if available
      let failedSessions = Array.isArray(recent_failed_callbacks) ? recent_failed_callbacks.slice(0, 5) : []
      let attachments = [],
        snapErrors = []
      for (let sessionId of failedSessions) {
        // Session snapshot
        let sessionSnap = null,
          callbacksInfo = null
        try {
          const snapResp = await axios.get(`${baseUrl}/admin/session/${sessionId}`, { headers, timeout: 15000 })
          sessionSnap = snapResp.data
        } catch (e) {
          snapErrors.push({ sessionId, type: "snapshot", error: e.message })
        }
        try {
          // Callbacks details view (optional, tolerate errors)
          const cbResp = await axios.get(`${baseUrl}/admin/callbacks?sessionId=${sessionId}`, { headers, timeout: 10000 })
          callbacksInfo = cbResp.data
        } catch (e) {
          callbacksInfo = { sessionId, error: e.message }
        }
        attachments.push({ sessionId, sessionSnap, callbacksInfo })
      }
      setContext("callback_slo_incident", {
        status: "incident",
        breachDetails,
        attachments,
        snapErrors,
        sloSnapshot: sloMetrics,
        timestamp: new Date().toISOString()
      })
      setContext("open_incident", {
        type: "callback_slo_breach",
        breachDetails,
        attachments,
        triggeredAt: new Date().toISOString()
      })
      console.error("Callback SLO breach detected. Incident opened with session artifacts.")
    } else {
      setContext("callback_slo_status", {
        status: "ok",
        metrics: { callback_delivery_success_rate, p95_callback_delivery_latency },
        timestamp: new Date().toISOString()
      })
      console.log("Callback SLOs normal. Metrics ready for dashboard tile.")
    }
    setContext("runbook_note", "Queries Honeypot /admin/slo, opens incident with failing sessions if callback SLO breach. Uses x-admin-key.")
  } catch (e) {
    setContext("callback_slo_status", { status: "error", error: e.message, timestamp: new Date().toISOString() })
    process.exit(1)
  }
})()
