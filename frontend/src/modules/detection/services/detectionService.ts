const API_BASE = process.env.REACT_APP_API_BASE || "http://localhost:8000";

async function postAnalyze(event: Record<string, any>) {
  const res = await fetch(`${API_BASE}/api/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(event),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Analyze failed: ${res.status} ${text}`);
  }

  return res.json();
}

const detectionService = {
  async getModels() {
    // Model metadata isn't exposed; return minimal info.
    return [
      { id: 1, name: "risk_classifier", algorithm: "Ensemble", status: "Online" },
    ];
  },

  async getSummary() {
    // Perform a single analyze call as a sanity check to report summary-like info.
    const sample = {
      event_id: "SAMPLE-1",
      timestamp: new Date().toISOString(),
      src_ip: "192.168.1.1",
      dest_ip: "10.0.0.1",
      protocol: "TCP",
      severity: "HIGH",
      event_category: "Network",
      asset_criticality: "HIGH",
      threat_score: 50,
      cvss_score: 0.0,
      matched_ioc: false,
      mitre_technique_id: "T1059",
      mitre_tactic: "Execution",
      user: "unknown",
      host: "host1",
      src_port: 12345,
      dest_port: 443,
    };

    const resp = await postAnalyze(sample);
    return {
      threatsDetected: 1,
      confidence: resp.prediction?.confidence ?? 0,
      top_prediction: resp.prediction?.top_predictions?.[0] ?? null,
    };
  },

  async getPredictions() {
    // For local dev show a small list of real predictions from the backend.
    const samples = [
      {
        event_id: "SAMPLE-1",
        timestamp: new Date().toISOString(),
        src_ip: "192.168.1.10",
        dest_ip: "10.0.0.5",
        protocol: "TCP",
        severity: "HIGH",
        event_category: "Network",
        asset_criticality: "HIGH",
        threat_score: 75,
        cvss_score: 7.5,
        matched_ioc: false,
        mitre_technique_id: "T1059",
        mitre_tactic: "Execution",
        user: "u1",
        host: "h1",
        src_port: 52345,
        dest_port: 443,
      },
    ];

    const results = [];
    for (const s of samples) {
      try {
        const r = await postAnalyze(s);
        results.push({
          id: s.event_id,
          timestamp: new Date(r.timing?.prediction_time ?? s.timestamp).toLocaleTimeString(),
          source: "Live",
          prediction: r.prediction?.prediction ?? "Unknown",
          confidence: Math.round((r.prediction?.confidence ?? 0) * 100),
          severity: "High",
          model_name: r.processing?.model_name ?? r.prediction?.model_name ?? null,
          top_predictions: (r.prediction?.top_predictions ?? []).map((t: any) => ({ label: t.label, confidence: Math.round((t.confidence ?? 0) * 100) })),
        });
      } catch (e) {
        results.push({
          id: s.event_id,
          timestamp: new Date(s.timestamp).toLocaleTimeString(),
          source: "Live",
          prediction: "Error",
          confidence: 0,
          severity: "Low",
        });
      }
    }

    return results;
  },
};

export default detectionService;