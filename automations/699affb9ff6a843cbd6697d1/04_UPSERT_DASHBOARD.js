// 04_UPSERT_DASHBOARD -- Upsert Value Dashboard artifact with DRY_RUN/UPSERT_MODE/idempotence/retry, env-driven API paths
const axios = require("axios")

;(async () => {
  const env = process.env
  const dashPayload = typeof getContext === "function" ? getContext("value_dashboard.dashboard_payload") : undefined
  const { TURBOTIC_API_BASE, TURBOTIC_API_TOKEN, DASHBOARD_ID, DRY_RUN, UPSERT_MODE, TURBOTIC_DASHBOARD_GET, TURBOTIC_DASHBOARD_PATCH, TURBOTIC_DASHBOARD_POST, TURBOTIC_DASHBOARD_VIS_PATCH } = env
  let dryRun = String(DRY_RUN).toLowerCase() === "true"
  let upsertMode = String(UPSERT_MODE).toLowerCase() === "true"

  function emit(status) {
    setContext("value_dashboard.dashboard_id", DASHBOARD_ID)
    setContext("value_dashboard.upsert_status", status)
  }
  if (!dashPayload || !DASHBOARD_ID) {
    emit("error")
    console.error(JSON.stringify({ step: "04_UPSERT_DASHBOARD", result: "fail", reason: "no-dashboard-payload", ts: new Date().toISOString() }))
    process.exit(1)
  }

  if (dryRun) {
    emit("skipped_dryrun")
    console.log(JSON.stringify({ step: "04_UPSERT_DASHBOARD", mode: "dryrun", ts: new Date().toISOString(), payload: dashPayload }))
    return
  }

  const api = axios.create({ baseURL: TURBOTIC_API_BASE, headers: { Authorization: `Bearer ${TURBOTIC_API_TOKEN}` }, timeout: 10000 })

  // Choose paths via override env or fallback to default
  const getPath = TURBOTIC_DASHBOARD_GET || `/dashboards/${DASHBOARD_ID}`
  const patchPath = TURBOTIC_DASHBOARD_PATCH || `/dashboards/${DASHBOARD_ID}`
  const postPath = TURBOTIC_DASHBOARD_POST || "/dashboards"

  // Helper: GET/PATCH/POST with upsert logic and improved error logging
  async function upsertDashboard() {
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        // GET by ID
        const getRes = await api.get(getPath)
        if (getRes.status === 200 && getRes.data && Object.keys(getRes.data).length) {
          await api.patch(patchPath, dashPayload)
          emit("updated")
          console.log(JSON.stringify({ step: "04_UPSERT_DASHBOARD", result: "updated", dashId: DASHBOARD_ID, attempt, ts: new Date().toISOString() }))
          return
        }
      } catch (e) {
        if (e.response && e.response.status === 404) {
          // Not found, so create
          try {
            await api.post(postPath, dashPayload)
            emit("created")
            console.log(JSON.stringify({ step: "04_UPSERT_DASHBOARD", result: "created", dashId: DASHBOARD_ID, attempt, ts: new Date().toISOString() }))
            return
          } catch (err) {
            if (attempt === 3) {
              // Improved error logging with response body
              const details = err.response && err.response.data ? err.response.data : String(err)
              emit("error")
              console.error(JSON.stringify({ step: "04_UPSERT_DASHBOARD", result: "fail", dashId: DASHBOARD_ID, attempt, ts: new Date().toISOString(), error: details }))
              process.exit(1)
            }
          }
        } else if ((e.code === "ECONNABORTED" || (e.response && e.response.status >= 500)) && attempt < 3) {
          await new Promise(res => setTimeout(res, attempt * 800))
          continue
        } else {
          emit("error")
          let details = e.response && e.response.data ? e.response.data : String(e)
          console.error(JSON.stringify({ step: "04_UPSERT_DASHBOARD", result: "fail", dashId: DASHBOARD_ID, attempt, ts: new Date().toISOString(), error: details }))
          process.exit(1)
        }
      }
    }
    emit("error")
    console.error(JSON.stringify({ step: "04_UPSERT_DASHBOARD", result: "fail-no-create", dashId: DASHBOARD_ID, ts: new Date().toISOString() }))
    process.exit(1)
  }

  if (!upsertMode) {
    emit("noop_disabled")
    console.log(JSON.stringify({ step: "04_UPSERT_DASHBOARD", result: "noop_disabled", ts: new Date().toISOString() }))
    return
  }

  try {
    await upsertDashboard()
  } catch (e) {
    emit("error")
    let details = e && e.message ? e.message : String(e)
    if (e.response && e.response.data) details = e.response.data
    console.error(JSON.stringify({ step: "04_UPSERT_DASHBOARD", result: "fail", dashId: DASHBOARD_ID, ts: new Date().toISOString(), error: details }))
    process.exit(1)
  }
})()
