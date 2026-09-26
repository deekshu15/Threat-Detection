import { useEffect, useMemo, useState } from "react";

import AutoAwesomeRoundedIcon from "@mui/icons-material/AutoAwesomeRounded";
import { Box, Divider, Grid, Stack, Typography } from "@mui/material";

import GlassSurface from "../../components/ui/GlassSurface";
import PageHeader from "../../components/ui/PageHeader/PageHeader";
import analyticsService from "../analytics/services/analyticsService";
import { getSecurityEvents, type SecurityEvent } from "./eventsService";

function AiSummaryPage() {
  const [analytics, setAnalytics] = useState<{
    total_events: number;
    critical_events: number;
    high_events: number;
    medium_events: number;
    low_events: number;
    average_risk_score: number;
    severity_distribution: Array<{ severity: string; count: number }>;
    attack_type_frequency: Array<{ attack_type: string; count: number }>;
    tool_distribution: Array<{ tool: string; count: number }>;
  } | null>(null);
  const [recentEvents, setRecentEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function loadSummary() {
    try {
      setLoading(true);
      setError(null);
      const [data, events] = await Promise.all([
        analyticsService.getAnalytics(),
        getSecurityEvents(20),
      ]);
      setAnalytics(data);
      setRecentEvents(events);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load AI summary.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadSummary();
  }, []);

  const summaryText = useMemo(() => {
    if (!analytics || analytics.total_events === 0) {
      return "No security events are currently available. Run a scanner or connect a data source to generate a summary.";
    }

    const parts: string[] = [];
    parts.push(`${analytics.total_events} security events analyzed.`);

    if (analytics.critical_events > 0) {
      parts.push(`${analytics.critical_events} critical findings require immediate investigation.`);
    }
    if (analytics.high_events > 0) {
      parts.push(`${analytics.high_events} high-risk findings need attention.`);
    }

    if (analytics.attack_type_frequency.length > 0) {
      parts.push(`${analytics.attack_type_frequency[0].attack_type} is the most common attack type (${analytics.attack_type_frequency[0].count} occurrences).`);
    }

    if (analytics.tool_distribution.length > 0) {
      parts.push(`${analytics.tool_distribution[0].tool} is the most active detection source.`);
    }

    const latestHighRisk = recentEvents.find((event) => ["critical", "high"].includes(event.severity?.toLowerCase() || ""));
    if (latestHighRisk) {
      parts.push(`The latest high-priority evidence is ${latestHighRisk.attack_type || "an active security finding"}${latestHighRisk.target ? ` affecting ${latestHighRisk.target}` : ""}.`);
    }

    parts.push(`Average risk score across all events is ${analytics.average_risk_score}.`);

    return parts.join(" ");
  }, [analytics, recentEvents]);

  const topThreat = useMemo(() => {
    if (!analytics || analytics.attack_type_frequency.length === 0) return "N/A";
    return analytics.attack_type_frequency[0].attack_type;
  }, [analytics]);

  if (loading) {
    return (
      <Box sx={{ minHeight: "calc(100vh - 180px)", pb: { xs: 3, md: 5 } }}>
        <PageHeader title="AI Summary" subtitle="Automated security posture analysis." />
        <Box sx={{ display: "flex", justifyContent: "center", alignItems: "center", minHeight: 300 }}>
          <Typography color="text.secondary">Loading summary...</Typography>
        </Box>
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ minHeight: "calc(100vh - 180px)", pb: { xs: 3, md: 5 } }}>
        <PageHeader title="AI Summary" subtitle="Automated security posture analysis." />
        <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 2, minHeight: 300, justifyContent: "center" }}>
          <Typography color="#fca5a5">{error}</Typography>
        </Box>
      </Box>
    );
  }

  return (
    <Box sx={{ minHeight: "calc(100vh - 180px)", pb: { xs: 3, md: 5 } }}>
      <PageHeader title="AI Summary" subtitle="Automated security posture analysis based on current events." />

      <Grid container columnSpacing={{ xs: 0, lg: 3 }} rowSpacing={{ xs: 3, lg: 0 }} alignItems="stretch" sx={{ mt: 1.5 }}>
        <Grid size={{ xs: 12, lg: 8 }}>
          <GlassSurface sx={{ p: { xs: 2.5, md: 3.25 }, height: "100%", transition: "border-color 180ms ease, box-shadow 180ms ease", "&:hover": { borderColor: "#22d3ee", boxShadow: "0 0 0 2px rgba(34, 211, 238, 0.18)" } }}>
            <Stack direction="row" spacing={1.5} alignItems="center" mb={2}>
              <AutoAwesomeRoundedIcon sx={{ color: "#22d3ee", fontSize: 28 }} />
              <Typography variant="h6" fontWeight={700}>
                Security Overview
              </Typography>
            </Stack>
            <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8 }}>
              {summaryText}
            </Typography>

            {recentEvents.length > 0 && (
              <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1.5 }}>
                Evidence window: the latest {recentEvents.length} recorded security event{recentEvents.length === 1 ? "" : "s"}.
              </Typography>
            )}

            <Divider sx={{ my: 3, borderColor: "rgba(255,255,255,0.08)" }} />

            <Grid container spacing={2.25} sx={{ mt: 0.25 }}>
              <Grid size={{ xs: 12, sm: 6, md: 3 }}>
                <Box sx={{ p: 1.5, minHeight: 88, borderRadius: 2.5, bgcolor: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.06)" }}>
                  <Typography variant="caption" color="text.secondary">Total Events</Typography>
                  <Typography variant="h5" fontWeight={800} sx={{ mt: 0.4 }}>{analytics?.total_events ?? 0}</Typography>
                </Box>
              </Grid>
              <Grid size={{ xs: 12, sm: 6, md: 3 }}>
                <Box sx={{ p: 1.5, minHeight: 88, borderRadius: 2.5, bgcolor: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.18)" }}>
                  <Typography variant="caption" color="#fca5a5">Critical</Typography>
                  <Typography variant="h5" fontWeight={800} sx={{ mt: 0.4, color: "#ef4444" }}>{analytics?.critical_events ?? 0}</Typography>
                </Box>
              </Grid>
              <Grid size={{ xs: 12, sm: 6, md: 3 }}>
                <Box sx={{ p: 1.5, minHeight: 88, borderRadius: 2.5, bgcolor: "rgba(251,113,133,0.08)", border: "1px solid rgba(251,113,133,0.18)" }}>
                  <Typography variant="caption" color="#fca5a5">High Risk</Typography>
                  <Typography variant="h5" fontWeight={800} sx={{ mt: 0.4, color: "#fb7185" }}>{analytics?.high_events ?? 0}</Typography>
                </Box>
              </Grid>
              <Grid size={{ xs: 12, sm: 6, md: 3 }}>
                <Box sx={{ p: 1.5, minHeight: 88, borderRadius: 2.5, bgcolor: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.06)" }}>
                  <Typography variant="caption" color="text.secondary">Avg Risk</Typography>
                  <Typography variant="h5" fontWeight={800} sx={{ mt: 0.4 }}>{analytics?.average_risk_score ?? 0}</Typography>
                </Box>
              </Grid>
            </Grid>
          </GlassSurface>
        </Grid>

        <Grid size={{ xs: 12, lg: 4 }}>
          <GlassSurface sx={{ p: { xs: 2.5, md: 3.25 }, height: "100%", transition: "border-color 180ms ease, box-shadow 180ms ease", "&:hover": { borderColor: "#22d3ee", boxShadow: "0 0 0 2px rgba(34, 211, 238, 0.18)" } }}>
            <Typography variant="subtitle1" fontWeight={700} gutterBottom>
              Recommended Focus
            </Typography>
            <Stack spacing={1.25} sx={{ mt: 1.5 }}>
              {analytics && analytics.total_events > 0 ? (
                <>
                  <Box sx={{ px: 1, py: 0.8, borderRadius: 1.75, bgcolor: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.18)" }}>
                    <Typography variant="body2" fontWeight={700} sx={{ color: "#fca5a5" }}>
                      Investigate critical findings first
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {analytics.critical_events} critical event{analytics.critical_events !== 1 ? "s" : ""} require immediate attention.
                    </Typography>
                  </Box>
                  <Box sx={{ px: 1, py: 0.8, borderRadius: 1.75, bgcolor: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.08)" }}>
                    <Typography variant="body2" fontWeight={700}>
                      Address top threat: {topThreat}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {analytics.attack_type_frequency[0]?.count ?? 0} occurrences detected.
                    </Typography>
                  </Box>
                  <Box sx={{ px: 1, py: 0.8, borderRadius: 1.75, bgcolor: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.08)" }}>
                    <Typography variant="body2" fontWeight={700}>
                      Review tool coverage
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {analytics.tool_distribution.length} tool{analytics.tool_distribution.length !== 1 ? "s" : ""} contributed detections.
                    </Typography>
                  </Box>
                </>
              ) : (
                <Typography variant="body2" color="text.secondary">
                  No data available for recommendations.
                </Typography>
              )}
            </Stack>
          </GlassSurface>
        </Grid>
      </Grid>
    </Box>
  );
}

export default AiSummaryPage;
