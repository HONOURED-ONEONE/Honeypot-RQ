const axios = require("axios")
const crypto = require("crypto")

;(async () => {
  const HONEYPOT_BASE_URL = process.env.HONEYPOT_BASE_URL
  const HONEYPOT_ADMIN_KEY = process.env.HONEYPOT_ADMIN_KEY
  const SESSION_ID = process.env.SESSION_ID
  const EVIDENCE_STORE_ENDPOINT = process.env.EVIDENCE_STORE_ENDPOINT
  const PARTNER_ENDPOINT = process.env.PARTNER_ENDPOINT
  const DRY_RUN = String(process.env.DRY_RUN || "").toLowerCase() === "true"

  // Masking helper
  function maskSecret(value) {
    if (!value || typeof value !== "string") return value
    return value.length <= 6 ? "*".repeat(value.length) : value.substring(0, 2) + "***" + value.slice(-2)
  }

  const startTime = Date.now()
  let callbackResponse
  let forwardResult = { success: false, status: null, latency: null, error: null }

  try {
    if (!HONEYPOT_BASE_URL || !HONEYPOT_ADMIN_KEY || !SESSION_ID) {
      throw new Error("Missing required environment variables.")
    }

    const url = `${HONEYPOT_BASE_URL.replace(/\/$/, "")}/admin/callbacks?sessionId=${encodeURIComponent(SESSION_ID)}`
    console.log(`[FINAL_CALLBACK_FORWARD] Fetching callback artifacts from ${url} (using masked key: ${maskSecret(HONEYPOT_ADMIN_KEY)})`)

    callbackResponse = await axios.get(url, {
      headers: { "x-admin-key": HONEYPOT_ADMIN_KEY }
    })
    const payload = callbackResponse && callbackResponse.data ? callbackResponse.data : null
    setContext("final_callback_payload", payload)

    if (!payload || !payload.finalReport) {
      console.log("[FINAL_CALLBACK_FORWARD] No finalReport found in callback payload. Step will exit.")
      setContext("final_callback_forwarded", false)
      return
    }

    // Decide endpoint
    const dest = EVIDENCE_STORE_ENDPOINT || PARTNER_ENDPOINT
    if (!dest) {
      console.log("[FINAL_CALLBACK_FORWARD] No forwarding endpoint (EVIDENCE_STORE_ENDPOINT or PARTNER_ENDPOINT) configured. Skipping forward.")
      setContext("final_callback_forwarded", false)
      return
    }

    console.log(`[FINAL_CALLBACK_FORWARD] Forwarding finalReport to: ${dest.replace(/([\w-]{4})([\w-]+)([\w-]{4})/, (m, a, b, c) => a + "***" + c)}...`)

    if (DRY_RUN) {
      console.log("[FINAL_CALLBACK_FORWARD] DRY_RUN is enabled -- Would POST but skipping actual send.")
      setContext("final_callback_forwarded", "dry-run")
      return
    }

    // Forward finalReport
    const fwdStart = Date.now()
    const fwdResp = await axios.post(dest, payload.finalReport, {
      headers: { "Content-Type": "application/json" },
      timeout: 20000
    })
    const latency = Date.now() - fwdStart
    forwardResult = {
      success: true,
      status: fwdResp.status,
      latency,
      error: null
    }
    setContext("final_callback_forwarded", true)
    console.log(`[FINAL_CALLBACK_FORWARD] Forward successful: status=${fwdResp.status}, latency=${latency}ms`)
  } catch (err) {
    forwardResult = {
      ...forwardResult,
      error: err && err.stack ? err.stack.substring(0, 860) : String(err)
    }
    setContext("final_callback_forwarded", false)
    console.error("[FINAL_CALLBACK_FORWARD] ERROR:", err && err.message ? err.message : err)
  } finally {
    // Audit log (mask secrets, never emit payload/PII, redact endpoints)
    const elapsed = Date.now() - startTime
    const auditLog = {
      step: "Final Callback Artifact Forwarder",
      source: "Honeypot",
      session: maskSecret(process.env.SESSION_ID),
      dest: (EVIDENCE_STORE_ENDPOINT || PARTNER_ENDPOINT || "").replace(/([\w-]{4})([\w-]+)([\w-]{4})/, (m, a, b, c) => a + "***" + c),
      dry_run: DRY_RUN,
      result: forwardResult,
      elapsed_ms: elapsed
    }
    console.log("[FINAL_CALLBACK_FORWARD] AUDIT_LOG", JSON.stringify(auditLog))
  }
})()
