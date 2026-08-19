import { type AnalyticsData, getSecurityEvents } from "../../shared/eventsService";

const delay = (ms: number) =>
  new Promise((resolve) => setTimeout(resolve, ms));

async function computeAnalytics(): Promise<AnalyticsData> {
  const events = await getSecurityEvents(500);
  const totalEvents = events.length;

  const severityCounts: Record<string, number> = {};
  const attackTypeCounts: Record<string, number> = {};
  const toolCounts: Record<string, number> = {};
  let riskSum = 0;
  let riskCount = 0;

  for (const event of events) {
    severityCounts[event.severity || "Unknown"] = (severityCounts[event.severity || "Unknown"] || 0) + 1;

    if (event.attack_type) {
      attackTypeCounts[event.attack_type] = (attackTypeCounts[event.attack_type] || 0) + 1;
    }

    if (event.tool) {
      toolCounts[event.tool] = (toolCounts[event.tool] || 0) + 1;
    }

    if (typeof event.risk_score === "number") {
      riskSum += event.risk_score;
      riskCount += 1;
    }
  }

  const criticalEvents = severityCounts["Critical"] || 0;
  const highEvents = severityCounts["High"] || 0;
  const mediumEvents = severityCounts["Medium"] || 0;
  const lowEvents = severityCounts["Low"] || 0;

  const severityDistribution = Object.entries(severityCounts)
    .map(([severity, count]) => ({ severity, count }))
    .sort((a, b) => b.count - a.count);

  const attackTypeFrequency = Object.entries(attackTypeCounts)
    .map(([attack_type, count]) => ({ attack_type, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  const toolDistribution = Object.entries(toolCounts)
    .map(([tool, count]) => ({ tool, count }))
    .sort((a, b) => b.count - a.count);

  return {
    success: true,
    total_events: totalEvents,
    critical_events: criticalEvents,
    high_events: highEvents,
    medium_events: mediumEvents,
    low_events: lowEvents,
    average_risk_score: riskCount > 0 ? Math.round((riskSum / riskCount) * 100) / 100 : 0,
    severity_distribution: severityDistribution,
    attack_type_frequency: attackTypeFrequency,
    tool_distribution: toolDistribution,
  };
}

const analyticsService = {
  async getAnalytics() {
    await delay(200);
    return computeAnalytics();
  },

  async getExecutiveMetrics() {
    await delay(200);
    const analytics = await computeAnalytics();
    return [
      { title: "Total Threats", value: analytics.total_events.toLocaleString(), trend: 0 },
      { title: "Critical Alerts", value: String(analytics.critical_events), trend: 0 },
      { title: "High Risk", value: String(analytics.high_events), trend: 0 },
      { title: "Average Risk Score", value: String(analytics.average_risk_score), trend: 0 },
    ];
  },

  async getThreatTrend() {
    await delay(200);
    const events = await getSecurityEvents(500);
    const counts: Record<string, number> = {};
    for (const event of events) {
      const date = event.timestamp?.split("T")[0] || "Unknown";
      counts[date] = (counts[date] || 0) + 1;
    }
    return Object.entries(counts)
      .map(([month, threats]) => ({ month, threats }))
      .sort((a, b) => a.month.localeCompare(b.month))
      .slice(-30);
  },

  async getRiskTrend() {
    await delay(200);
    const events = await getSecurityEvents(500);
    const byDate: Record<string, { sum: number; count: number }> = {};
    for (const event of events) {
      const date = event.timestamp?.split("T")[0] || "Unknown";
      if (typeof event.risk_score === "number") {
        byDate[date] = byDate[date] || { sum: 0, count: 0 };
        byDate[date].sum += event.risk_score;
        byDate[date].count += 1;
      }
    }
    return Object.entries(byDate)
      .map(([month, { sum, count }]) => ({ month, risk: count > 0 ? Math.round((sum / count) * 100) / 100 : 0 }))
      .sort((a, b) => a.month.localeCompare(b.month))
      .slice(-30);
  },

  async getAttackCategories() {
    await delay(200);
    const analytics = await computeAnalytics();
    return analytics.attack_type_frequency.slice(0, 10);
  },

  async getSourceAnalysis() {
    await delay(200);
    const events = await getSecurityEvents(500);
    const sourceCounts: Record<string, number> = {};
    for (const event of events) {
      const src = event.source || "Unknown";
      sourceCounts[src] = (sourceCounts[src] || 0) + 1;
    }
    return Object.entries(sourceCounts)
      .map(([source, events]) => ({ source, events }))
      .sort((a, b) => b.events - a.events)
      .slice(0, 10);
  },

  async getModelPerformance() {
    await delay(200);
    return [];
  },

  async getMitreCoverage() {
    await delay(200);
    return [];
  },
};

export default analyticsService;
