// 04_UPSERT_DASHBOARD -- Upsert Value Dashboard artifact with DRY_RUN/UPSERT_MODE/idempotence/retry
const axios = require("axios")

;(async () => {
  const env = process.env
  const dashPayload = typeof getContext === "function" ? getContext("value_dashboard.dashboard_payload") : undefined
  const { TURBOTIC_API_BASE, TURBOTIC_API_TOKEN, DASHBOARD_ID, DRY_RUN, UPSERT_MODE } = env
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

  // Helper: GET/PATCH/POST with upsert logic and retry
  async function upsertDashboard() {
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        // 1. Try get by ID (assume /dashboards/{id}); fallback to list+filter if 404
        const getRes = await api.get(`/dashboards/${DASHBOARD_ID}`)
        if (getRes.status === 200 && getRes.data && Object.keys(getRes.data).length) {
          await api.patch(`/dashboards/${DASHBOARD_ID}`, dashPayload)
          emit("updated")
          console.log(JSON.stringify({ step: "04_UPSERT_DASHBOARD", result: "updated", dashId: DASHBOARD_ID, attempt, ts: new Date().toISOString() }))
          return
        }
      } catch (e) {
        if (e.response && e.response.status === 404) {
          // Not found, so create
          try {
            await api.post("/dashboards", dashPayload)
            emit("created")
            console.log(JSON.stringify({ step: "04_UPSERT_DASHBOARD", result: "created", dashId: DASHBOARD_ID, attempt, ts: new Date().toISOString() }))
            return
          } catch (err) {
            if (attempt === 3) throw err
          }
        } else if ((e.code === "ECONNABORTED" || (e.response && e.response.status >= 500)) && attempt < 3) {
          await new Promise(res => setTimeout(res, attempt * 800)) // exp-backoff
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
    console.error(JSON.stringify({ step: "04_UPSERT_DASHBOARD", result: "fail", dashId: DASHBOARD_ID, ts: new Date().toISOString(), error: details }))
    process.exit(1)
  }
})()
