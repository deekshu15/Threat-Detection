const API_BASE =
  import.meta.env.VITE_API_URL ||
  "http://127.0.0.1:8000";

export interface SecurityEvent {
  event_id: string;
  timestamp: string;
  source: string;
  tool?: string;
  target?: string;
  source_ip?: string;
  destination_ip?: string;
  country?: string;
  attack_type?: string;
  severity?: string;
  risk_score?: number;
  status?: string;
  port?: number;
  protocol?: string;
  service?: string;
  description?: string;
  recommendation?: string;
  ingestion_time?: string;
}

export async function saveSecurityEvent(event: SecurityEvent): Promise<{ success: boolean; event: SecurityEvent }> {
  const response = await fetch(`${API_BASE}/api/events`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(event),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || "Failed to save security event.");
  }

  return response.json();
}

export async function getSecurityEvents(limit = 100): Promise<SecurityEvent[]> {
  const response = await fetch(`${API_BASE}/api/events?limit=${limit}`);

  if (!response.ok) {
    throw new Error("Failed to load security events.");
  }

  const data = await response.json();
  return data.events ?? [];
}
