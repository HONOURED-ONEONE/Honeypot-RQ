const axios = require("axios")

// Finalize SLO guard: scheduled check, opens incident with artifact if breach. Restricted to Ops.
;(async () => {
  try {
    setContext("required_role", "Ops") // UI should enforce only SRE/Ops can run
    const baseUrl = process.env.ORCHESTRATOR_BASE_URL
    const apiKey = process.env.ORCHESTRATOR_API_KEY
    if (!baseUrl || !apiKey) {
      setContext("finalize_slo_status", { error: "Missing ORCHESTRATOR_BASE_URL or ORCHESTRATOR_API_KEY." })
      process.exit(1)
    }
    const headers = { Authorization: `Bearer ${apiKey}` }
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
    let breach = false
    let breachDetails = {}
    // SLO thresholds
    if ((finalize_success_rate !== undefined && finalize_success_rate < 99.9) || (p95_finalize_latency !== undefined && p95_finalize_latency > (target_finalize_latency || 5))) {
      breach = true
      breachDetails = { finalize_success_rate, p95_finalize_latency, thresholds: { minSuccess: 99.9, maxP95: target_finalize_latency || 5 } }
    }
    let incidentCount = 0
    if (breach) {
      incidentCount = 1
    }
    setContext("finalize_slo_metrics", { finalize_success_rate, p95_finalize_latency, incidentCount, timestamp: new Date().toISOString() })
    if (breach) {
      // Attempt to fetch timelines for top delayed sessions if listed
      let delayedSessions = sessions_waiting_for_report || []
      let timelines = []
      for (let s of delayedSessions.slice(0, 5)) {
        try {
          let resp = await axios.get(`${baseUrl}/admin/session/${s}`, { headers, timeout: 15000 })
          timelines.push({ sessionId: s, timeline: resp.data })
        } catch (e) {
          timelines.push({ sessionId: s, error: e.message })
        }
      }
      setContext("finalize_slo_incident", {
        status: "incident",
        breachDetails,
        timelines,
        sloSnapshot: slo,
        timestamp: new Date().toISOString()
      })
      setContext("open_incident", {
        type: "finalize_slo_breach",
        breachDetails,
        attachments: { timelines, sloSnapshot: slo },
        triggeredAt: new Date().toISOString()
      })
      console.error("Finalize SLO breach detected. Incident with timelines opened.")
    } else {
      setContext("finalize_slo_status", {
        status: "ok",
        finalize_success_rate,
        p95_finalize_latency,
        timestamp: new Date().toISOString()
      })
      console.log("Finalize SLOs are normal. Metrics ready for dashboard.")
    }
    setContext("runbook_note", "Checks /admin/slo finalize SLOs, opens incident and attaches timelines for session delays if SLO breached. Ops restricted. Outputs metrics for dashboard.")
  } catch (e) {
    setContext("finalize_slo_status", { status: "error", error: e.message, timestamp: new Date().toISOString() })
    process.exit(1)
  }
})()
