// 01_VALIDATE_ENV - Atomic, declarative env and context validation for Value Dashboard pipeline

const REQUIRED_ENVS = ["DASHBOARD_ID", "DASHBOARD_NAME", "DASHBOARD_DESC", "ROLE_EXECUTIVE", "SRC_INTAKE", "SRC_CASE_EXEC", "SRC_CB_SLO", "SRC_FIN_SLO", "SRC_EVID_AUD", "TURBOTIC_API_BASE", "TURBOTIC_API_TOKEN", "DRY_RUN", "UPSERT_MODE"]

function isTruthy(val) {
  return !!val && String(val).trim() !== ""
}

;(async () => {
  let errorCount = 0,
    warnCount = 0,
    errors = [],
    warns = []
  const envSnapshot = {}
  for (const k of REQUIRED_ENVS) {
    if (k === "TURBOTIC_API_TOKEN") continue // never log tokens
    envSnapshot[k] = process.env[k] || ""
    if (!isTruthy(process.env[k])) {
      errors.push(`Missing or empty env: ${k}`)
      errorCount++
    }
  }
  // Try to validate getContext exists and each SRC_*
  let sourceMiss = 0
  let sources = [process.env.SRC_INTAKE, process.env.SRC_CASE_EXEC, process.env.SRC_CB_SLO, process.env.SRC_FIN_SLO, process.env.SRC_EVID_AUD]
  let sourcesOk = 0
  if (typeof getContext === "function") {
    for (const src of sources) {
      try {
        const v = getContext(src)
        if (!v) {
          warns.push(`No context value for ${src}`)
          warnCount++
          sourceMiss++
        } else {
          sourcesOk++
        }
      } catch (e) {
        warns.push(`Error reading context for ${src}: ${String(e)}`)
        warnCount++
        sourceMiss++
      }
    }
  } else {
    warns.push("getContext() not available; skipping context source validation.")
    warnCount++
  }
  // Emit context
  setContext("value_dashboard.env_snapshot", envSnapshot)
  setContext("value_dashboard.env_verified", errorCount === 0)
  // Final status/effects
  if (errorCount > 0) {
    console.error(JSON.stringify({ step: "01_VALIDATE_ENV", result: "fail", ts: new Date().toISOString(), errorCount, errors, warnCount, warns, dashId: process.env.DASHBOARD_ID || "" }))
    setContext("value_dashboard.env_verified", false)
    process.exit(1)
  } else {
    console.log(JSON.stringify({ step: "01_VALIDATE_ENV", result: "ENV OK", dashId: process.env.DASHBOARD_ID, ts: new Date().toISOString(), errorCount, warnCount, warns }))
  }
})()
