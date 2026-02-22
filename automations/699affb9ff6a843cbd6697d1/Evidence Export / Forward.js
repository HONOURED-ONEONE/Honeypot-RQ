// Evidence Export / Forward - operator menu, triggered by Case Report Assembler output
const crypto = require("crypto")

;(async () => {
  try {
    setContext("required_role", "Ops") // UI should enforce role restriction
    // Check if report artifact from previous step is available and success trigger
    const reportArtifact = getContext("report_artifact")
    const exportTrigger = getContext("trigger_evidence_export")
    if (!exportTrigger || !reportArtifact) {
      setContext("evidence_export_status", { error: "Report artifact not available / not ready. Cannot proceed." })
      process.exit(1)
    }
    // Operator action menu (simulate manual choice via input env var or context)
    const operatorAction = process.env.OPERATOR_ACTION || getContext("operator_action") // 'export','forward','archive'
    // Audit info
    const operatorId = process.env.TURBOTIC_OPERATOR_ID || "unknown"
    const timestamp = new Date().toISOString()
    const fingerprint = crypto.createHash("sha256").update(JSON.stringify(reportArtifact)).digest("hex")

    let outputStatus = { action: operatorAction || "export", operator: operatorId, timestamp, payloadFingerprint: fingerprint }
    let externalEndpoint = process.env.PARTNER_ENDPOINT
    let evidenceStoreEndpoint = process.env.EVIDENCE_STORE_ENDPOINT
    let response = null
    if (operatorAction === "forward" && externalEndpoint) {
      // Forward to partner system via HTTP POST
      const axios = require("axios")
      try {
        response = await axios.post(externalEndpoint, reportArtifact, { headers: { "Content-Type": "application/json" }, timeout: 15000 })
        outputStatus.forwardStatus = response.status
      } catch (e) {
        outputStatus.forwardError = e.message
      }
    }
    if (operatorAction === "archive" && evidenceStoreEndpoint) {
      // Archive via HTTP POST
      const axios = require("axios")
      try {
        response = await axios.post(evidenceStoreEndpoint, reportArtifact, { headers: { "Content-Type": "application/json" }, timeout: 15000 })
        outputStatus.archiveStatus = response.status
      } catch (e) {
        outputStatus.archiveError = e.message
      }
    }
    setContext("evidence_export_audit", outputStatus)
    // (a) Export JSON - always as artifact, regardless of operator action
    setContext("evidence_export_artifact", reportArtifact)
    setContext("runbook_note", "Operator can export, forward to partner system, or archive report. Every action is logged for audit with identity, timestamp, fingerprint. Ops-only access.")
    console.log("Evidence export action:", operatorAction, outputStatus)
  } catch (e) {
    setContext("evidence_export_status", { status: "error", error: e.message, timestamp: new Date().toISOString() })
    process.exit(1)
  }
})()
