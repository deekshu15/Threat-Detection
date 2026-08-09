const API_BASE =
  import.meta.env.VITE_API_BASE ||
  "http://localhost:8000";

export interface DashboardMetadata {
  filename: string;
  rows: number;
  columns: number;
  dataset_type: string;
  available_columns?: string[];
}

export interface DashboardSummary {
  total_events: number;
  benign_events: number;
  threat_events: number;
  threat_percentage: number;
  label_column: string | null;
}

export interface DistributionItem {
  name: string;
  value: number;
}

export interface TrendItem {
  date: string;
  events: number;
}

export interface RecentEvent {
  timestamp: string | null;
  source: string | null;
  destination: string | null;
  threat: string | null;
  severity: string | null;
}

export interface DashboardData {
  success: boolean;
  metadata: DashboardMetadata;
  summary: DashboardSummary;
  severity: DistributionItem[];
  attack_distribution: DistributionItem[];
  trend: TrendItem[];
  recent_events: RecentEvent[];
}

export async function getDashboardData(): Promise<DashboardData> {
  const response = await fetch(
    `${API_BASE}/api/dashboard`
  );

  if (!response.ok) {
    let message = "Failed to load dashboard data.";

    try {
      const error = await response.json();

      if (typeof error.detail === "string") {
        message = error.detail;
      } else if (error.detail?.message) {
        message = error.detail.message;
      }
    } catch {
      // Keep default message
    }

    throw new Error(message);
  }

  return response.json();
}