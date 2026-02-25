const axios = require("axios")

// Finalize SLO guard: scheduled check, opens incident with artifacts if breach. Restricted to Ops.
;(async () => {
  try {
    setContext("required_role", "Ops")
    // Use new Honeypot admin API endpoint and key
    const baseUrl = process.env.HONEYPOT_BASE_URL
    const adminKey = process.env.HONEYPOT_ADMIN_KEY
    if (!baseUrl || !adminKey) {
      setContext("finalize_slo_status", { error: "Missing HONEYPOT_BASE_URL or HONEYPOT_ADMIN_KEY." })
      process.exit(1)
    }
    const headers = { "x-admin-key": adminKey }
    // Query SLO metrics
    let slo = null
    try {
      const sloResp = await axios.get(`${baseUrl}/admin/slo`, { headers, timeout: 15000 })
      slo = sloResp.data
    } catch (e) {
      setContext("finalize_slo_status", { error: "Failed to query /admin/slo", detail: e.message })
      process.exit(1)
    }
    // Evaluate finalize SLOs
    const { finalize_success_rate, p95_finalize_latency, target_finalize_latency, sessions_waiting_for_report } = slo || {}
    let breach = false,
      breachDetails = {}
    if ((finalize_success_rate !== undefined && finalize_success_rate < 99.9) || (p95_finalize_latency !== undefined && p95_finalize_latency > (target_finalize_latency || 5))) {
      breach = true
      breachDetails = { finalize_success_rate, p95_finalize_latency, thresholds: { minSuccess: 99.9, maxP95: target_finalize_latency || 5 } }
    }
    let incidentCount = breach ? 1 : 0
    setContext("finalize_slo_metrics", { finalize_success_rate, p95_finalize_latency, incidentCount, timestamp: new Date().toISOString() })
    if (breach) {
      // For sessions_waiting_for_report if present, fetch snapshot + timeline
      let delayedSessions = Array.isArray(sessions_waiting_for_report) ? sessions_waiting_for_report.slice(0, 5) : []
      let artifacts = [],
        snapErrors = []
      for (let s of delayedSessions) {
        let sessionSnap = null,
          timeline = null
        try {
          const snapResp = await axios.get(`${baseUrl}/admin/session/${s}`, { headers, timeout: 15000 })
          sessionSnap = snapResp.data
        } catch (e) {
          snapErrors.push({ sessionId: s, type: "snapshot", error: e.message })
        }
        try {
          // Timeline is optional, tolerate failure
          const tlResp = await axios.get(`${baseUrl}/admin/session/${s}/timeline`, { headers, timeout: 12000 })
          timeline = tlResp.data
        } catch (e) {
          timeline = { sessionId: s, error: e.message }
        }
        artifacts.push({ sessionId: s, sessionSnap, timeline })
      }
      setContext("finalize_slo_incident", {
        status: "incident",
        breachDetails,
        artifacts,
        snapErrors,
        sloSnapshot: slo,
        timestamp: new Date().toISOString()
      })
      setContext("open_incident", {
        type: "finalize_slo_breach",
        breachDetails,
        attachments: { artifacts },
        triggeredAt: new Date().toISOString()
      })
      console.error("Finalize SLO breach detected. Incident opened with session artifacts.")
    } else {
      setContext("finalize_slo_status", {
        status: "ok",
        finalize_success_rate,
        p95_finalize_latency,
        timestamp: new Date().toISOString()
      })
      console.log("Finalize SLOs normal. Metrics ready for dashboard tile.")
    }
    setContext("runbook_note", "Checks Honeypot /admin/slo finalize SLOs, attaches session artifacts for delays if breached. Uses x-admin-key.")
  } catch (e) {
    setContext("finalize_slo_status", { status: "error", error: e.message, timestamp: new Date().toISOString() })
    process.exit(1)
  }
})()
