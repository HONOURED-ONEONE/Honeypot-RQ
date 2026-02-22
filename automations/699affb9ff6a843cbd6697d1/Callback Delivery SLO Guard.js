const axios = require("axios")

// Scheduled SLO monitoring, every 1 min; restricted to SRE/Ops role.
;(async () => {
  try {
    setContext("required_role", "Ops") // Turbotic UI to enforce restriction for operations role
    const baseUrl = process.env.ORCHESTRATOR_BASE_URL
    const apiKey = process.env.ORCHESTRATOR_API_KEY
    if (!baseUrl || !apiKey) {
      setContext("callback_slo_status", { error: "Missing ORCHESTRATOR_BASE_URL or ORCHESTRATOR_API_KEY." })
      process.exit(1)
    }
    const headers = { Authorization: `Bearer ${apiKey}` }
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
    const { callback_delivery_success_rate, p95_callback_delivery_latency } = sloMetrics || {}
    let slaBreached = false
    let breachDetails = {}
    // SLO thresholds
    if ((callback_delivery_success_rate !== undefined && callback_delivery_success_rate < 99.9) || (p95_callback_delivery_latency !== undefined && p95_callback_delivery_latency > sloMetrics.target_callback_latency)) {
      slaBreached = true
      breachDetails = { callback_delivery_success_rate, p95_callback_delivery_latency, thresholds: { minSuccess: 99.9, maxLatency: sloMetrics.target_callback_latency } }
    }
    let incidentCount = 0
    if (slaBreached) {
      incidentCount = 1
    }
    setContext("callback_slo_metrics", { callback_delivery_success_rate, p95_callback_delivery_latency, incidentCount, timestamp: new Date().toISOString() })
    if (slaBreached) {
      // Gather artifacts
      let callbacksSnapshot = null
      try {
        const callbacksResp = await axios.get(`${baseUrl}/admin/callbacks?limit=50`, { headers, timeout: 15000 })
        callbacksSnapshot = callbacksResp.data
      } catch (e) {
        callbacksSnapshot = { error: "Failed to fetch callbacks snapshot", detail: e.message }
      }
      setContext("callback_slo_incident", {
        status: "incident",
        breachDetails,
        callbacksSnapshot,
        sloSnapshot: sloMetrics,
        timestamp: new Date().toISOString()
      })
      setContext("open_incident", {
        type: "callback_slo_breach",
        breachDetails,
        attachments: { callbacksSnapshot, sloSnapshot: sloMetrics },
        triggeredAt: new Date().toISOString()
      })
      console.error("Callback SLO breach detected. Incident opened with attached metrics and snapshot.")
    } else {
      setContext("callback_slo_status", {
        status: "ok",
        metrics: { callback_delivery_success_rate, p95_callback_delivery_latency },
        timestamp: new Date().toISOString()
      })
      console.log("Callback SLOs normal. Metrics ready for dashboard tile.")
    }
    setContext("runbook_note", "This step queries /admin/slo to monitor callback reliability, opens incident if delivery or latency SLO breached. Ops role restricted. Metrics exposed to dashboard.")
  } catch (e) {
    setContext("callback_slo_status", { status: "error", error: e.message, timestamp: new Date().toISOString() })
    process.exit(1)
  }
})()
