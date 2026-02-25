// Atomic patch: After polling finishes (either report ready or timeout/incident), aggregate exec KPIs from poll history & report
// Assume polling logic, reporting, audit, and incidents are already implemented above

const pollHistory = getContext("case_report_pollHistory") || [] // Array of poll results
const pollStartTime = getContext("case_report_pollStartTime")
const pollEndTime = getContext("case_report_pollEndTime")
const report = getContext("report_artifact") // Final report JSON (if ready)

// Accumulate KPI metrics
let conversationCount = pollHistory.length
let confirmedScamPct = 0
let avgTimeToFinalReport = 0
let avgDistinctIOCPerCase = 0
let topIOCCategories = []

if (report) {
  // Assume report has isScam, IOC details, and timing fields
  confirmedScamPct = report.isScam ? 100 : 0
  avgTimeToFinalReport = pollEndTime && pollStartTime ? (new Date(pollEndTime) - new Date(pollStartTime)) / 1000 : 0
  if (report.iocCategories && Array.isArray(report.iocCategories)) {
    // Aggregate distinct and top categories
    avgDistinctIOCPerCase = report.iocCategories.length
    // Count frequency
    const freq = {}
    report.iocCategories.forEach(cat => {
      freq[cat] = (freq[cat] || 0) + 1
    })
    topIOCCategories = Object.entries(freq)
      .sort((a, b) => b[1] - a[1])
      .map(([cat]) => cat)
      .slice(0, 3)
  }
}

setContext("case_report_exec_metrics", {
  conversationCount,
  confirmedScamPct,
  avgTimeToFinalReport,
  avgDistinctIOCPerCase,
  topIOCCategories,
  timestamp: new Date().toISOString()
})

// Existing outputs for dashboard tile wiring remain unchanged
// - setContext('report_artifact', report)
// - setContext('case_report_status', ...)
// - setContext('case_report_audit', ...)
