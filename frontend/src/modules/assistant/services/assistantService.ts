import { getSecurityEvents } from "../../shared/eventsService";

const delay = (ms: number) =>
  new Promise((resolve) => setTimeout(resolve, ms));

const assistantService = {
  async getMessages() {
    await delay(200);
    return [
      {
        id: 1,
        sender: "assistant" as const,
        content:
          "Hello. I am your AI Security Assistant. I can help investigate threats, explain detections, summarize incidents, and generate reports based on your actual security data.",
        timestamp: "09:00",
      },
    ];
  },

  async getSuggestions() {
    await delay(200);
    return [
      { id: 1, title: "Investigate Threat", prompt: "What are the critical threats?" },
      { id: 2, title: "Summarize Events", prompt: "Summarize today's security events." },
      { id: 3, title: "Top Attack", prompt: "Which attack type is most common?" },
      { id: 4, title: "Generate Report", prompt: "Generate an executive security report." },
    ];
  },

  async getConversations() {
    await delay(200);
    return [
      { id: 1, title: "Threat Investigation", updatedAt: "Today" },
      { id: 2, title: "Executive Report", updatedAt: "Yesterday" },
    ];
  },

  async ask(question: string) {
    await delay(300);
    const events = await getSecurityEvents(200);

    const lower = question.toLowerCase();
    if (lower.includes("critical") || lower.includes("highest risk")) {
      const criticals = events.filter((e) => (e.severity || "").toLowerCase() === "critical");
      if (criticals.length === 0) {
        return `No critical threats found among ${events.length} events.`;
      }
      const top = criticals[0];
      return `${criticals.length} critical event${criticals.length > 1 ? "s" : ""} found. Highest risk: ${top.attack_type || "Unknown"} targeting ${top.target || top.destination_ip || "Unknown"} with risk score ${top.risk_score ?? "N/A"}.`;
    }

    if (lower.includes("target") || lower.includes("highest risk target")) {
      const targetCounts: Record<string, number> = {};
      for (const e of events) {
        const t = e.target || e.destination_ip || "Unknown";
        targetCounts[t] = (targetCounts[t] || 0) + 1;
      }
      const sorted = Object.entries(targetCounts).sort((a, b) => b[1] - a[1]);
      if (sorted.length === 0) return "No target data available.";
      return `${sorted[0][0]} is the most frequent target (${sorted[0][1]} events).`;
    }

    if (lower.includes("nmap")) {
      const nmapEvents = events.filter((e) => e.tool === "Nmap");
      if (nmapEvents.length === 0) return "No Nmap scan events recorded yet.";
      const latest = nmapEvents[0];
      return `Latest Nmap scan found ${nmapEvents.length} event(s). Most recent: ${latest.attack_type || "Unknown"} on ${latest.target || "Unknown"} (${latest.port ?? "N/A"}/${latest.protocol ?? "N/A"}).`;
    }

    if (lower.includes("summarize") || lower.includes("summary")) {
      const severityCounts: Record<string, number> = {};
      for (const e of events) {
        severityCounts[e.severity || "Unknown"] = (severityCounts[e.severity || "Unknown"] || 0) + 1;
      }
      const parts = [`${events.length} security events analyzed.`];
      if (severityCounts["Critical"]) parts.push(`${severityCounts["Critical"]} critical findings.`);
      if (severityCounts["High"]) parts.push(`${severityCounts["High"]} high-risk findings.`);
      return parts.join(" ");
    }

    if (lower.includes("common") || lower.includes("most common")) {
      const attackCounts: Record<string, number> = {};
      for (const e of events) {
        if (e.attack_type) {
          attackCounts[e.attack_type] = (attackCounts[e.attack_type] || 0) + 1;
        }
      }
      const sorted = Object.entries(attackCounts).sort((a, b) => b[1] - a[1]);
      if (sorted.length === 0) return "No attack type data available.";
      return `${sorted[0][0]} is the most common attack type (${sorted[0][1]} occurrences).`;
    }

    if (lower.includes("investigate") || lower.includes("first")) {
      const criticals = events.filter((e) => (e.severity || "").toLowerCase() === "critical");
      const highs = events.filter((e) => (e.severity || "").toLowerCase() === "high");
      if (criticals.length > 0) {
        return `Investigate ${criticals.length} critical finding(s) first. Top priority: ${criticals[0].attack_type || "Unknown"} on ${criticals[0].target || "Unknown"}.`;
      }
      if (highs.length > 0) {
        return `No critical findings. ${highs.length} high-risk finding(s) should be reviewed next.`;
      }
      return "No urgent findings requiring immediate investigation.";
    }

    if (lower.includes("report") || lower.includes("executive")) {
      const criticals = events.filter((e) => (e.severity || "").toLowerCase() === "critical");
      const highs = events.filter((e) => (e.severity || "").toLowerCase() === "high");
      return `Executive Security Report: ${events.length} events analyzed. ${criticals.length} critical, ${highs.length} high-risk. Immediate action required on critical findings.`;
    }

    return `I analyzed ${events.length} security events. Ask me about critical threats, attack summaries, Nmap results, or targets.`;
  },
};

export default assistantService;
