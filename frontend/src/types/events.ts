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

export interface AnalyticsData {
  success: boolean;
  total_events: number;
  critical_events: number;
  high_events: number;
  medium_events: number;
  low_events: number;
  average_risk_score: number;
  severity_distribution: Array<{ severity: string; count: number }>;
  attack_type_frequency: Array<{ attack_type: string; count: number }>;
  tool_distribution: Array<{ tool: string; count: number }>;
}
