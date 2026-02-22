// 05_ASSIGN_EXEC_ROLE - Assign Value Dashboard to Executive role, emit audit, log all outcomes, DRY_RUN aware
const axios = require("axios")

;(async () => {
  const env = process.env
  const { TURBOTIC_API_BASE, TURBOTIC_API_TOKEN, DASHBOARD_ID, DASHBOARD_NAME, ROLE_EXECUTIVE, DRY_RUN } = env
  const dryRun = String(DRY_RUN).toLowerCase() === "true"
  if (!DASHBOARD_ID || !ROLE_EXECUTIVE || !TURBOTIC_API_BASE || !TURBOTIC_API_TOKEN) {
    setContext("value_dashboard.visibility_status", "error_missing_env")
    console.error(JSON.stringify({ step: "05_ASSIGN_EXEC_ROLE", result: "fail", reason: "missing_env", ts: new Date().toISOString() }))
    process.exit(1)
  }

  function emit(status) {
    setContext("value_dashboard.role_assigned", ROLE_EXECUTIVE)
    setContext("value_dashboard.visibility_status", status)
  }

  if (dryRun) {
    emit("skipped_dryrun")
    console.log(JSON.stringify({ step: "05_ASSIGN_EXEC_ROLE", result: "skipped_dryrun", ts: new Date().toISOString(), dashId: DASHBOARD_ID, role: ROLE_EXECUTIVE }))
    return
  }

  const api = axios.create({ baseURL: TURBOTIC_API_BASE, headers: { Authorization: `Bearer ${TURBOTIC_API_TOKEN}` }, timeout: 10000 })
  let roleId,
    dashboardFound = false,
    patchOk = false
  try {
    // 1. Fetch roles, find ROLE_EXECUTIVE
    const rolesRes = await api.get("/roles")
    const roles = rolesRes.data && Array.isArray(rolesRes.data) ? rolesRes.data : []
    const roleObj = roles.find(r => r.name === ROLE_EXECUTIVE)
    if (!roleObj || !roleObj.id) {
      emit("error_role_missing")
      console.error(JSON.stringify({ step: "05_ASSIGN_EXEC_ROLE", result: "fail", reason: "role_not_found", ts: new Date().toISOString() }))
      process.exit(1)
    }
    roleId = roleObj.id
    // 2. PATCH dashboard visibility (could PATCH /dashboards/{id} or PUT /dashboards/{id}/visibility)
    const visPatch = {
      id: DASHBOARD_ID,
      visibility: [roleId]
    }
    let visOk = false,
      patchRes
    for (let i = 0; i < 3; ++i) {
      try {
        patchRes = await api.patch(`/dashboards/${DASHBOARD_ID}/visibility`, visPatch)
        visOk = true
        break
      } catch (e) {
        if (i === 2) throw e
        await new Promise(r => setTimeout(r, 700 * i))
      }
    }
    if (!visOk || !patchRes || !patchRes.status || patchRes.status >= 300) {
      emit("error_patch_visibility")
      console.error(JSON.stringify({ step: "05_ASSIGN_EXEC_ROLE", result: "fail", reason: "patch_visibility", ts: new Date().toISOString(), res: patchRes && patchRes.data }))
      process.exit(1)
    }
    emit("granted")
    // AUDIT LOG CONTEXT
    // Collect tile IDs from context if available
    let tiles = []
    try {
      const t = typeof getContext === "function" ? getContext("value_dashboard.tiles") : null
      tiles = Array.isArray(t) ? t.map(x => x.id) : []
    } catch (_) {
      tiles = []
    }
    setContext("value_dashboard.publish_audit", {
      id: DASHBOARD_ID,
      name: DASHBOARD_NAME || "",
      role: ROLE_EXECUTIVE,
      publishedAt: new Date().toISOString(),
      tiles,
      sources: [env.SRC_INTAKE, env.SRC_CASE_EXEC, env.SRC_CB_SLO, env.SRC_FIN_SLO, env.SRC_EVID_AUD].filter(Boolean)
    })
    console.log(JSON.stringify({ step: "05_ASSIGN_EXEC_ROLE", result: "granted", dashId: DASHBOARD_ID, role: ROLE_EXECUTIVE, ts: new Date().toISOString() }))
  } catch (e) {
    emit("error")
    console.error(JSON.stringify({ step: "05_ASSIGN_EXEC_ROLE", result: "fail", ts: new Date().toISOString(), error: String(e) }))
    process.exit(1)
  }
})()
