import { type AnalyticsData, getSecurityEvents } from "../../shared/eventsService";

const API_BASE =
  import.meta.env.VITE_API_URL ||
  "http://127.0.0.1:8000";

const delay = (ms: number) =>
  new Promise((resolve) => setTimeout(resolve, ms));

async function fetchAnalytics(): Promise<AnalyticsData> {
  const response = await fetch(`${API_BASE}/api/analytics`);
  if (!response.ok) {
    throw new Error("Failed to load analytics from server.");
  }
  return response.json();
}


const analyticsService = {
  async getAnalytics() {
    await delay(200);
    return fetchAnalytics();
  },

  async getExecutiveMetrics() {
    await delay(200);
    const analytics = await fetchAnalytics();
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
    const analytics = await fetchAnalytics();
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
