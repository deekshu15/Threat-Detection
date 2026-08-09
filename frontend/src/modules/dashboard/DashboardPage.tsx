import React, {
  useEffect,
  useState,
} from "react";

import StatCard from "./components/StatCard";
import AttackDistribution from "./components/AttackDistribution";
import SeverityChart from "./components/SeverityChart";
import ThreatTrend from "./components/ThreatTrend";
import RecentEventsTable from "./components/RecentEventsTable";

import {
  getDashboardData,
  type DashboardData,
} from "./services/dashboardService";

export default function DashboardPage() {
  const [data, setData] =
    useState<DashboardData | null>(null);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState<string | null>(null);

  async function loadDashboard() {
    try {
      setLoading(true);
      setError(null);

      const result =
        await getDashboardData();

      setData(result);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to load dashboard data."
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadDashboard();
  }, []);

  if (loading) {
    return (
      <div style={pageStyle}>
        <div style={loadingStyle}>
          Loading threat intelligence dashboard...
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div style={pageStyle}>
        <div style={emptyContainer}>
          <div style={emptyIcon}>🛡</div>

          <h1 style={titleStyle}>
            No Threat Data Available
          </h1>

          <p style={descriptionStyle}>
            {error}
          </p>

          <button
            onClick={loadDashboard}
            style={buttonStyle}
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  if (!data) {
    return null;
  }

  const {
    metadata,
    summary,
    severity,
    attack_distribution,
    trend,
    recent_events,
  } = data;

  return (
    <div style={pageStyle}>
      {/* HEADER */}

      <div style={headerRow}>
        <div>
          <div style={breadcrumb}>
            Security Operations
            <span> / </span>
            Dashboard
          </div>

          <h1 style={titleStyle}>
            Cyber Threat Intelligence
            Dashboard
          </h1>

          <p style={descriptionStyle}>
            Real-time security analysis from the
            uploaded threat dataset.
          </p>
        </div>

        <button
          onClick={loadDashboard}
          style={refreshButton}
        >
          Refresh
        </button>
      </div>

      {/* DATASET INFO */}

      <div style={datasetBanner}>
        <div>
          <strong>Dataset:</strong>{" "}
          {metadata.filename}
        </div>

        <div>
          <strong>Type:</strong>{" "}
          {metadata.dataset_type}
        </div>

        <div>
          <strong>Rows:</strong>{" "}
          {metadata.rows.toLocaleString()}
        </div>

        <div>
          <strong>Columns:</strong>{" "}
          {metadata.columns.toLocaleString()}
        </div>
      </div>

      {/* STATISTICS */}

      <div style={statsGrid}>
        <StatCard
          title="Total Events"
          value={summary.total_events.toLocaleString()}
          subtitle="Processed security events"
        />

        <StatCard
          title="Threats Detected"
          value={summary.threat_events.toLocaleString()}
          subtitle={`${summary.threat_percentage}% of events`}
        />

        <StatCard
          title="Benign Events"
          value={summary.benign_events.toLocaleString()}
          subtitle="Normal / benign activity"
        />

        <StatCard
          title="Threat Rate"
          value={`${summary.threat_percentage}%`}
          subtitle="Based on dataset labels"
        />
      </div>

      {/* CHARTS */}

      <div style={twoColumnGrid}>
        <section style={panelStyle}>
          <h2 style={panelTitle}>
            Attack Distribution
          </h2>

          <AttackDistribution
            data={attack_distribution}
          />
        </section>

        <section style={panelStyle}>
          <h2 style={panelTitle}>
            Severity Distribution
          </h2>

          <SeverityChart
            data={severity}
          />
        </section>
      </div>

      {/* TREND */}

      <section style={panelStyle}>
        <h2 style={panelTitle}>
          Event Trend
        </h2>

        <ThreatTrend data={trend} />
      </section>

      {/* RECENT EVENTS */}

      <section style={panelStyle}>
        <h2 style={panelTitle}>
          Recent Security Events
        </h2>

        <RecentEventsTable
          data={recent_events}
        />
      </section>
    </div>
  );
}

/* ---------------------------------------------------------
   STYLES
--------------------------------------------------------- */

const pageStyle: React.CSSProperties = {
  minHeight: "100%",
  padding: "30px 36px 60px",
  background: "#0b0f14",
  color: "#ffffff",
};

const headerRow: React.CSSProperties = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "flex-start",
  gap: 20,
  marginBottom: 24,
};

const breadcrumb: React.CSSProperties = {
  color: "#788493",
  fontSize: 13,
  marginBottom: 12,
};

const titleStyle: React.CSSProperties = {
  margin: 0,
  fontSize: 30,
  fontWeight: 700,
};

const descriptionStyle: React.CSSProperties = {
  color: "#9ca7b5",
  marginTop: 8,
  fontSize: 14,
};

const refreshButton: React.CSSProperties = {
  border: "1px solid #536dfe",
  background: "#536dfe",
  color: "#ffffff",
  borderRadius: 8,
  padding: "10px 18px",
  cursor: "pointer",
};

const datasetBanner: React.CSSProperties = {
  display: "flex",
  flexWrap: "wrap",
  gap: 28,
  background: "#11161d",
  border: "1px solid #29313d",
  borderRadius: 12,
  padding: "16px 20px",
  marginBottom: 22,
  color: "#c5ced9",
  fontSize: 13,
};

const statsGrid: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns:
    "repeat(auto-fit, minmax(200px, 1fr))",
  gap: 16,
  marginBottom: 20,
};

const twoColumnGrid: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns:
    "repeat(auto-fit, minmax(320px, 1fr))",
  gap: 20,
  marginBottom: 20,
};

const panelStyle: React.CSSProperties = {
  background: "#11161d",
  border: "1px solid #29313d",
  borderRadius: 16,
  padding: 22,
  marginBottom: 20,
};

const panelTitle: React.CSSProperties = {
  marginTop: 0,
  marginBottom: 22,
  fontSize: 17,
  fontWeight: 600,
};

const loadingStyle: React.CSSProperties = {
  display: "flex",
  justifyContent: "center",
  alignItems: "center",
  minHeight: 500,
  color: "#9ca7b5",
};

const emptyContainer: React.CSSProperties = {
  minHeight: 600,
  display: "flex",
  flexDirection: "column",
  justifyContent: "center",
  alignItems: "center",
  textAlign: "center",
};

const emptyIcon: React.CSSProperties = {
  fontSize: 48,
  marginBottom: 20,
};

const buttonStyle: React.CSSProperties = {
  background: "#536dfe",
  border: "none",
  color: "#ffffff",
  padding: "10px 20px",
  borderRadius: 8,
  cursor: "pointer",
};