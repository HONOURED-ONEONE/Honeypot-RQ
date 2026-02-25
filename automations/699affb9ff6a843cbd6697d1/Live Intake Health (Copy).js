// Live Intake Health: Scheduled Health Endpoint Check for JS-Orchestrator
// Runs every 1 minute. Outputs health status for dashboard tile and audit/troubleshooting.

const axios = require("axios")

const orchestratorBaseUrl = process.env.ORCHESTRATOR_BASE_URL
const orchestratorApiKey = process.env.ORCHESTRATOR_API_KEY

if (!orchestratorBaseUrl || !orchestratorApiKey) {
  setContext("intake_health", {
    status: "error",
    error: "Missing required environment variable: ORCHESTRATOR_BASE_URL or ORCHESTRATOR_API_KEY."
  })
  console.error("Missing Orchestrator config for health check.")
  process.exit(1)
}

async function checkHealth() {
  try {
    const start = Date.now()
    const response = await axios.get(`${orchestratorBaseUrl}/health`, {
      headers: { Authorization: `Bearer ${orchestratorApiKey}` },
      timeout: 7000
    })
    const latency = Date.now() - start
    setContext("intake_health", {
      status: response.data.status || "unknown",
      healthPayload: response.data,
      code: response.status,
      latencyMs: latency,
      checkedAt: new Date().toISOString()
    })
    setContext("workflow_description", "Scheduled health check of JS-Orchestrator: GET /health every 1 min. Dashboard tile reflects status.")
    console.log(`Orchestrator health status: ${response.data.status || response.status} at ${latency}ms`)
  } catch (error) {
    setContext("intake_health", {
      status: "error",
      healthPayload: null,
      code: error.response?.status || "N/A",
      error: error.message,
      checkedAt: new Date().toISOString()
    })
    setContext("workflow_description", "Scheduled health check of JS-Orchestrator: GET /health every 1 min. Dashboard tile reflects status.")
    console.error("Orchestrator health check error:", error.message)
    process.exitCode = 2 // Mark as error but let workflow proceed for aggregation/monitoring.
  }
}

checkHealth()
