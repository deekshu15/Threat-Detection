import { useEffect, useMemo, useState } from "react";

import DownloadRoundedIcon from "@mui/icons-material/DownloadRounded";
import {
  Box,
  Button,
  Card,
  CardContent,
  FormControl,
  Grid,
  InputLabel,
  MenuItem,
  Select,
  Stack,
  Typography,
} from "@mui/material";

import analyticsService from "./services/analyticsService";
import type { AnalyticsData, SecurityEvent } from "../../types/events";
import { getSecurityEvents } from "../shared/eventsService";

type Range = "Last 24h" | "Last 7 days" | "Last 30 days";

const countries = [
  "All Countries",
  "Japan",
  "Brazil",
  "Nigeria",
  "South Korea",
  "Russia",
  "Germany",
  "China",
  "United Kingdom",
  "Iran",
  "United States",
  "Australia",
  "India",
];

function AnalyticsCard({ title, wide = false, children }: { title: string; wide?: boolean; children?: React.ReactNode }) {
  return (
    <Card sx={{ height: wide ? 306 : 394, borderColor: "rgba(36, 207, 226, .16)", bgcolor: "rgba(10, 16, 29, .72)" }}>
      <CardContent sx={{ p: { xs: 2, md: 2.5 } }}>
        <Typography variant="h6" fontWeight={700}>{title}</Typography>
        {children}
      </CardContent>
    </Card>
  );
}

function AnalyticsPage() {
  const [analytics, setAnalytics] = useState<AnalyticsData | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [range, setRange] = useState<Range>("Last 24h");
  const [country, setCountry] = useState("All Countries");

  async function loadAnalytics() {
    try {
      setLoading(true);
      setError(null);
      const [result, eventData] = await Promise.all([
        analyticsService.getAnalytics(),
        getSecurityEvents(1000),
      ]);
      setAnalytics(result);
      setEvents(eventData);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load analytics data.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadAnalytics();

    const refreshTimer = window.setInterval(() => {
      loadAnalytics();
    }, 30_000);

    return () => window.clearInterval(refreshTimer);
  }, []);

  const exportReport = () => {
    const report = `Threat Analytics Report\nTime range,${range}\nCountry,${country}\nTotal Events,${displayEvents.length}\n`;
    const blob = new Blob([report], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "threat-analytics-report.csv";
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const displayEvents = useMemo(() => {
    const now = Date.now();
    const rangeMs: Record<Range, number> = {
      "Last 24h": 24 * 60 * 60 * 1000,
      "Last 7 days": 7 * 24 * 60 * 60 * 1000,
      "Last 30 days": 30 * 24 * 60 * 60 * 1000,
    };

    return events.filter((event) => {
      const timestamp = Date.parse(event.timestamp);
      const inRange = Number.isNaN(timestamp) || now - timestamp <= rangeMs[range];
      const inCountry = country === "All Countries" || event.country === country;
      return inRange && inCountry;
    });
  }, [events, range, country]);

  const displayAnalytics = useMemo<AnalyticsData | null>(() => {
    if (!analytics) return null;
    const severityCounts: Record<string, number> = {};
    const attackCounts: Record<string, number> = {};
    const toolCounts: Record<string, number> = {};
    let riskTotal = 0;
    let riskCount = 0;

    for (const event of displayEvents) {
      const severity = event.severity || "Unknown";
      severityCounts[severity] = (severityCounts[severity] || 0) + 1;
      if (event.attack_type) attackCounts[event.attack_type] = (attackCounts[event.attack_type] || 0) + 1;
      if (event.tool) toolCounts[event.tool] = (toolCounts[event.tool] || 0) + 1;
      if (typeof event.risk_score === "number") {
        riskTotal += event.risk_score;
        riskCount += 1;
      }
    }

    const byCount = (entries: Record<string, number>) => Object.entries(entries).sort((a, b) => b[1] - a[1]);
    const countSeverity = (name: string) => displayEvents.filter((event) => event.severity?.toLowerCase() === name.toLowerCase()).length;

    return {
      ...analytics,
      total_events: displayEvents.length,
      critical_events: countSeverity("critical"),
      high_events: countSeverity("high"),
      medium_events: countSeverity("medium"),
      low_events: countSeverity("low"),
      average_risk_score: riskCount ? Math.round((riskTotal / riskCount) * 100) / 100 : 0,
      severity_distribution: Object.entries(severityCounts).map(([severity, count]) => ({ severity, count })),
      attack_type_frequency: byCount(attackCounts).map(([attack_type, count]) => ({ attack_type, count })),
      tool_distribution: byCount(toolCounts).map(([tool, count]) => ({ tool, count })),
    };
  }, [analytics, displayEvents]);

  const severityData = useMemo(() => {
    if (!displayAnalytics) return [];
    const map: Record<string, number> = {};
    for (const item of displayAnalytics.severity_distribution) {
      map[item.severity] = item.count;
    }
    return [
      { name: "Critical", value: map["Critical"] || 0, color: "#ef4444" },
      { name: "High", value: map["High"] || 0, color: "#fb7185" },
      { name: "Medium", value: map["Medium"] || 0, color: "#fbbf24" },
      { name: "Low", value: map["Low"] || 0, color: "#34d399" },
    ];
  }, [displayAnalytics]);

  const attackData = useMemo(() => {
    if (!displayAnalytics) return [];
    return displayAnalytics.attack_type_frequency.map((item) => ({ name: item.attack_type, value: item.count }));
  }, [displayAnalytics]);

  const toolData = useMemo(() => {
    if (!displayAnalytics) return [];
    return displayAnalytics.tool_distribution.map((item) => ({ name: item.tool, value: item.count }));
  }, [displayAnalytics]);

  const trendData = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const event of displayEvents) {
      const date = event.timestamp?.slice(0, 10) || "Unknown";
      counts[date] = (counts[date] || 0) + 1;
    }
    return Object.entries(counts).sort(([a], [b]) => a.localeCompare(b)).slice(-7);
  }, [displayEvents]);

  const targetData = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const event of displayEvents) {
      const target = event.target || event.destination_ip;
      if (target) counts[target] = (counts[target] || 0) + 1;
    }
    return Object.entries(counts).sort(([, a], [, b]) => b - a).slice(0, 5);
  }, [displayEvents]);

  const countryData = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const event of displayEvents) {
      if (event.country) counts[event.country] = (counts[event.country] || 0) + 1;
    }
    return Object.entries(counts).sort(([, a], [, b]) => b - a).slice(0, 5);
  }, [displayEvents]);

  if (loading) {
    return (
      <Box sx={{ display: "flex", justifyContent: "center", alignItems: "center", minHeight: 400 }}>
        <Typography color="text.secondary">Loading analytics...</Typography>
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", minHeight: 400, gap: 2 }}>
        <Typography color="#fca5a5">{error}</Typography>
        <Button onClick={loadAnalytics} size="small" variant="outlined">Retry</Button>
      </Box>
    );
  }

  if (!displayAnalytics || displayAnalytics.total_events === 0) {
    return (
      <Box>
        <Stack
          direction={{ xs: "column", md: "row" }}
          alignItems={{ md: "center" }}
          justifyContent="space-between"
          rowGap={2}
          mb={4}
          width="100%"
        >
          <Typography variant="h4" fontWeight={800}>
            Threat <Box component="span" color="#12cfe2">Analytics</Box>
          </Typography>
        </Stack>
        <Card sx={{ bgcolor: "rgba(10, 16, 29, .72)", borderColor: "rgba(36, 207, 226, .16)" }}>
          <CardContent sx={{ textAlign: "center", py: 6 }}>
            <Typography variant="body1" color="text.secondary" fontWeight={600}>
              No security events available.
            </Typography>
            <Typography variant="body2" color="#6f87a8" sx={{ mt: 1 }}>
              Run a scanner or connect a data source to populate analytics.
            </Typography>
          </CardContent>
        </Card>
      </Box>
    );
  }

  return (
    <Box>
      <Stack
        direction={{ xs: "column", md: "row" }}
        alignItems={{ md: "center" }}
        justifyContent="space-between"
        rowGap={2}
        mb={4}
        width="100%"
      >
        <Typography variant="h4" fontWeight={800}>
          Threat <Box component="span" color="#12cfe2">Analytics</Box>
        </Typography>

        <Stack direction={{ xs: "column", sm: "row" }} gap={1} sx={{ ml: { md: "auto" } }}>
          <FormControl size="small" sx={{ minWidth: 120 }}>
            <InputLabel>Time range</InputLabel>
            <Select value={range} label="Time range" onChange={(event) => setRange(event.target.value as Range)}>
              {["Last 24h", "Last 7 days", "Last 30 days"].map((item) => (
                <MenuItem key={item} value={item}>{item}</MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 140 }}>
            <InputLabel>Country</InputLabel>
            <Select value={country} label="Country" onChange={(event) => setCountry(event.target.value)}>
              {countries.map((item) => (
                <MenuItem key={item} value={item}>{item}</MenuItem>
              ))}
            </Select>
          </FormControl>
          <Button size="small" variant="contained" startIcon={<DownloadRoundedIcon fontSize="small" />} onClick={exportReport} sx={{ minWidth: 88, px: 1.25 }}>
            Export
          </Button>
        </Stack>
      </Stack>

      <Grid container spacing={2.5}>
        <Grid size={{ xs: 12, lg: 6 }}>
          <AnalyticsCard title="Attack Type Frequency">
            <Box sx={{ mt: 2 }}>
              {attackData.length === 0 ? (
                <Typography variant="body2" color="text.secondary">No attack data available.</Typography>
              ) : (
                <Stack spacing={1.2}>
                  {attackData.slice(0, 8).map((item) => (
                    <Box key={item.name} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <Box sx={{ width: 120, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        <Typography variant="body2" fontWeight={600}>{item.name}</Typography>
                      </Box>
                      <Box sx={{ flex: 1, height: 8, bgcolor: "rgba(255,255,255,0.06)", borderRadius: 999, overflow: "hidden" }}>
                        <Box sx={{ width: `${Math.min((item.value / (attackData[0]?.value || 1)) * 100, 100)}%`, height: "100%", bgcolor: "#22d3ee", borderRadius: 999 }} />
                      </Box>
                      <Typography variant="body2" color="text.secondary" sx={{ minWidth: 32, textAlign: "right" }}>{item.value}</Typography>
                    </Box>
                  ))}
                </Stack>
              )}
            </Box>
          </AnalyticsCard>
        </Grid>

        <Grid size={{ xs: 12, lg: 6 }}>
          <AnalyticsCard title="Severity Distribution">
            <Box sx={{ mt: 2 }}>
              {severityData.length === 0 ? (
                <Typography variant="body2" color="text.secondary">No severity data available.</Typography>
              ) : (
                <Stack spacing={1.2}>
                  {severityData.map((item) => (
                    <Box key={item.name} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <Box sx={{ width: 80 }}>
                        <Typography variant="body2" fontWeight={600}>{item.name}</Typography>
                      </Box>
                      <Box sx={{ flex: 1, height: 8, bgcolor: "rgba(255,255,255,0.06)", borderRadius: 999, overflow: "hidden" }}>
                        <Box sx={{ width: `${Math.min((item.value / (severityData[0]?.value || 1)) * 100, 100)}%`, height: "100%", bgcolor: item.color, borderRadius: 999 }} />
                      </Box>
                      <Typography variant="body2" color="text.secondary" sx={{ minWidth: 32, textAlign: "right" }}>{item.value}</Typography>
                    </Box>
                  ))}
                </Stack>
              )}
            </Box>
          </AnalyticsCard>
        </Grid>

        <Grid size={{ xs: 12, lg: 6 }}>
          <AnalyticsCard title="Tool-wise Findings">
            <Box sx={{ mt: 2 }}>
              {toolData.length === 0 ? (
                <Typography variant="body2" color="text.secondary">No tool data available.</Typography>
              ) : (
                <Stack spacing={1.2}>
                  {toolData.slice(0, 8).map((item) => (
                    <Box key={item.name} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <Box sx={{ width: 120, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        <Typography variant="body2" fontWeight={600}>{item.name}</Typography>
                      </Box>
                      <Box sx={{ flex: 1, height: 8, bgcolor: "rgba(255,255,255,0.06)", borderRadius: 999, overflow: "hidden" }}>
                        <Box sx={{ width: `${Math.min((item.value / (toolData[0]?.value || 1)) * 100, 100)}%`, height: "100%", bgcolor: "#a855f7", borderRadius: 999 }} />
                      </Box>
                      <Typography variant="body2" color="text.secondary" sx={{ minWidth: 32, textAlign: "right" }}>{item.value}</Typography>
                    </Box>
                  ))}
                </Stack>
              )}
            </Box>
          </AnalyticsCard>
        </Grid>

        <Grid size={{ xs: 12, lg: 6 }}>
          <AnalyticsCard title="Attack Trends Over Time">
            <Box sx={{ mt: 2 }}>
              <Typography variant="body2" color="text.secondary">
                {trendData.length > 0 ? trendData.map(([date, count]) => `${date}: ${count}`).join(" • ") : "No dated events available for the selected filters."}
              </Typography>
            </Box>
          </AnalyticsCard>
        </Grid>

        <Grid size={{ xs: 12, lg: 6 }}>
          <AnalyticsCard title="Device/Target-wise Attacks">
            <Box sx={{ mt: 2 }}>
              {targetData.length === 0 ? (
                <Typography variant="body2" color="text.secondary">No target data available.</Typography>
              ) : (
                <Stack spacing={1}>{targetData.map(([target, count]) => <Typography key={target} variant="body2" color="text.secondary">{target}: {count}</Typography>)}</Stack>
              )}
            </Box>
          </AnalyticsCard>
        </Grid>

        <Grid size={{ xs: 12, lg: 6 }}>
          <AnalyticsCard title="Country Distribution">
            <Box sx={{ mt: 2 }}>
              {countryData.length === 0 ? <Typography variant="body2" color="text.secondary">No country data available for the selected events.</Typography> : <Stack spacing={1}>{countryData.map(([name, count]) => <Typography key={name} variant="body2" color="text.secondary">{name}: {count}</Typography>)}</Stack>}
            </Box>
          </AnalyticsCard>
        </Grid>
      </Grid>
    </Box>
  );
}

export default AnalyticsPage;
