import { useEffect, useMemo, useState } from "react";

import { Box, Button, Chip, Grid, Stack, Typography } from "@mui/material";

import GlassSurface from "../../components/ui/GlassSurface";
import PageHeader from "../../components/ui/PageHeader/PageHeader";
import analyticsService from "../analytics/services/analyticsService";

function StatisticsPage() {
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
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function loadStats() {
    try {
      setLoading(true);
      setError(null);
      const data = await analyticsService.getAnalytics();
      setAnalytics(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load statistics.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadStats();
  }, []);

  const severityLegend = useMemo(() => {
    if (!analytics) {
      return [
        { name: "Critical", value: 0, color: "#ef4444" },
        { name: "High", value: 0, color: "#f97316" },
        { name: "Medium", value: 0, color: "#facc15" },
        { name: "Low", value: 0, color: "#22c55e" },
      ];
    }

    const map: Record<string, { name: string; value: number; color: string }> = {
      Critical: { name: "Critical", value: 0, color: "#ef4444" },
      High: { name: "High", value: 0, color: "#f97316" },
      Medium: { name: "Medium", value: 0, color: "#facc15" },
      Low: { name: "Low", value: 0, color: "#22c55e" },
    };

    for (const item of analytics.severity_distribution) {
      const key = item.severity.charAt(0).toUpperCase() + item.severity.slice(1).toLowerCase();
      if (map[key]) {
        map[key].value = item.count;
      }
    }

    return Object.values(map);
  }, [analytics]);

  const topAttack = useMemo(() => {
    if (!analytics || analytics.attack_type_frequency.length === 0) return "N/A";
    return analytics.attack_type_frequency[0].attack_type;
  }, [analytics]);

  const topTool = useMemo(() => {
    if (!analytics || analytics.tool_distribution.length === 0) return "N/A";
    return analytics.tool_distribution[0].tool;
  }, [analytics]);

  if (loading) {
    return (
      <Box sx={{ minHeight: "calc(100vh - 180px)", pb: { xs: 3, md: 5 } }}>
        <PageHeader title="Statistics" subtitle="Overview of threat severity distribution and attack origins." />
        <Box sx={{ display: "flex", justifyContent: "center", alignItems: "center", minHeight: 300 }}>
          <Typography color="text.secondary">Loading statistics...</Typography>
        </Box>
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ minHeight: "calc(100vh - 180px)", pb: { xs: 3, md: 5 } }}>
        <PageHeader title="Statistics" subtitle="Overview of threat severity distribution and attack origins." />
        <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 2, minHeight: 300, justifyContent: "center" }}>
          <Typography color="#fca5a5">{error}</Typography>
          <Button onClick={loadStats} size="small" variant="outlined">Retry</Button>
        </Box>
      </Box>
    );
  }

  const isEmpty = !analytics || analytics.total_events === 0;

  return (
    <Box sx={{ minHeight: "calc(100vh - 180px)", pb: { xs: 3, md: 5 } }}>
      <PageHeader
        title="Statistics"
        subtitle="Overview of threat severity distribution and attack origins."
      />

      <GlassSurface
        sx={{
          width: "100%",
          maxWidth: 1180,
          mx: "auto",
          mt: { xs: 3, md: 4 },
          borderRadius: 4,
          background: "rgba(8, 14, 28, 0.82)",
          boxShadow: "0 28px 70px rgba(0, 0, 0, 0.34)",
          transition: "border-color 180ms ease, box-shadow 180ms ease",
          "&:hover": {
            borderColor: "#22d3ee",
            boxShadow: "0 0 0 2px rgba(34, 211, 238, 0.18), 0 28px 70px rgba(0, 0, 0, 0.34)",
          },
          px: { xs: 2.5, md: 4 },
          py: { xs: 3, md: 3.5 },
        }}
      >
        {isEmpty ? (
          <Box sx={emptyChartSx}>
            <Typography variant="body2" sx={{ color: "text.secondary", fontWeight: 600 }}>
              No security events available.
            </Typography>
            <Typography variant="caption" sx={{ mt: 0.6, color: "#6f87a8" }}>
              Run a scanner or connect a data source to populate analytics.
            </Typography>
          </Box>
        ) : (
          <Box sx={{ display: "grid", gap: 3 }}>
            <Grid container spacing={2.25}>
              <Grid size={{ xs: 12, md: 7 }}>
                <Box sx={panelSx}>
                  <Typography variant="caption" sx={sectionLabelSx}>
                    SEVERITY DISTRIBUTION
                  </Typography>

                  <Stack direction="row" spacing={{ xs: 1.2, sm: 1.8 }} sx={{ flexWrap: "wrap", rowGap: 1.2, mt: 2 }}>
                    {severityLegend.map((item) => (
                      <Box key={item.name} sx={{ display: "inline-flex", alignItems: "center", gap: 0.7 }}>
                        <Box sx={{ width: 9, height: 9, borderRadius: "50%", bgcolor: item.color }} />
                        <Typography variant="body2" sx={{ color: "text.primary", fontWeight: 600 }}>
                          {item.name}: {item.value}
                        </Typography>
                      </Box>
                    ))}
                  </Stack>
                </Box>
              </Grid>

              <Grid size={{ xs: 12, md: 5 }}>
                <Box sx={panelSx}>
                  <Typography variant="caption" sx={sectionLabelSx}>
                    TOP ATTACK ORIGINS
                  </Typography>

                  <Box sx={{ mt: 2 }}>
                    {analytics.attack_type_frequency.length === 0 ? (
                      <Typography variant="body2" color="text.secondary">No attack data available.</Typography>
                    ) : (
                      <Stack spacing={1.2}>
                        {analytics.attack_type_frequency.slice(0, 5).map((item) => (
                          <Box key={item.attack_type} sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                            <Typography variant="body2" fontWeight={600}>{item.attack_type}</Typography>
                            <Chip size="small" label={item.count} sx={{ bgcolor: "rgba(34,211,238,0.08)", color: "#22d3ee", border: "1px solid rgba(34,211,238,0.28)", fontWeight: 700 }} />
                          </Box>
                        ))}
                      </Stack>
                    )}
                  </Box>
                </Box>
              </Grid>
            </Grid>

            <Grid container spacing={2.25}>
              <Grid size={{ xs: 12, sm: 6, md: 3 }}>
                <Box sx={statCardSx}>
                  <Typography variant="caption" sx={{ color: "#7891b2", letterSpacing: 1, fontWeight: 700 }}>
                    TOTAL EVENTS
                  </Typography>
                  <Typography variant="h4" sx={{ fontWeight: 800, mt: 0.5 }}>
                    {analytics.total_events.toLocaleString()}
                  </Typography>
                </Box>
              </Grid>
              <Grid size={{ xs: 12, sm: 6, md: 3 }}>
                <Box sx={statCardSx}>
                  <Typography variant="caption" sx={{ color: "#7891b2", letterSpacing: 1, fontWeight: 700 }}>
                    CRITICAL EVENTS
                  </Typography>
                  <Typography variant="h4" sx={{ fontWeight: 800, mt: 0.5, color: "#ef4444" }}>
                    {analytics.critical_events}
                  </Typography>
                </Box>
              </Grid>
              <Grid size={{ xs: 12, sm: 6, md: 3 }}>
                <Box sx={statCardSx}>
                  <Typography variant="caption" sx={{ color: "#7891b2", letterSpacing: 1, fontWeight: 700 }}>
                    HIGH RISK EVENTS
                  </Typography>
                  <Typography variant="h4" sx={{ fontWeight: 800, mt: 0.5, color: "#fb7185" }}>
                    {analytics.high_events}
                  </Typography>
                </Box>
              </Grid>
              <Grid size={{ xs: 12, sm: 6, md: 3 }}>
                <Box sx={statCardSx}>
                  <Typography variant="caption" sx={{ color: "#7891b2", letterSpacing: 1, fontWeight: 700 }}>
                    AVERAGE RISK SCORE
                  </Typography>
                  <Typography variant="h4" sx={{ fontWeight: 800, mt: 0.5 }}>
                    {analytics.average_risk_score}
                  </Typography>
                </Box>
              </Grid>
            </Grid>

            <Grid container spacing={2.25}>
              <Grid size={{ xs: 12, md: 6 }}>
                <Box sx={panelSx}>
                  <Typography variant="caption" sx={sectionLabelSx}>
                    MOST COMMON ATTACK
                  </Typography>
                  <Typography variant="h6" sx={{ fontWeight: 700, mt: 1 }}>
                    {topAttack}
                  </Typography>
                </Box>
              </Grid>
              <Grid size={{ xs: 12, md: 6 }}>
                <Box sx={panelSx}>
                  <Typography variant="caption" sx={sectionLabelSx}>
                    MOST ACTIVE TOOL
                  </Typography>
                  <Typography variant="h6" sx={{ fontWeight: 700, mt: 1 }}>
                    {topTool}
                  </Typography>
                </Box>
              </Grid>
            </Grid>
          </Box>
        )}
      </GlassSurface>
    </Box>
  );
}

const panelSx = {
  height: "100%",
  minHeight: 120,
  p: { xs: 2, md: 2.5 },
  borderRadius: 3,
  bgcolor: "rgba(255,255,255,0.02)",
  border: "1px solid rgba(255,255,255,0.07)",
};

const statCardSx = {
  height: "100%",
  minHeight: 120,
  p: { xs: 2, md: 2.5 },
  borderRadius: 3,
  bgcolor: "rgba(255,255,255,0.02)",
  border: "1px solid rgba(255,255,255,0.07)",
  display: "flex",
  flexDirection: "column" as const,
};

const sectionLabelSx = {
  display: "block",
  color: "#7891b2",
  letterSpacing: 1,
  fontWeight: 700,
};

const emptyChartSx = {
  minHeight: 172,
  mt: 2,
  px: 2,
  borderRadius: 2.5,
  border: "1px dashed rgba(120, 145, 178, 0.22)",
  bgcolor: "rgba(255,255,255,0.012)",
  display: "flex",
  flexDirection: "column",
  alignItems: "center",
  justifyContent: "center",
  textAlign: "center",
};

export default StatisticsPage;
