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
import type { AnalyticsData } from "../../types/events";

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
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [range, setRange] = useState<Range>("Last 24h");
  const [country, setCountry] = useState("All Countries");

  async function loadAnalytics() {
    try {
      setLoading(true);
      setError(null);
      const result = await analyticsService.getAnalytics();
      setAnalytics(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load analytics data.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadAnalytics();
  }, []);

  const exportReport = () => {
    const report = `Threat Analytics Report\nTime range,${range}\nCountry,${country}\nTotal Events,${analytics?.total_events ?? 0}\n`;
    const blob = new Blob([report], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "threat-analytics-report.csv";
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const severityData = useMemo(() => {
    if (!analytics) return [];
    const map: Record<string, number> = {};
    for (const item of analytics.severity_distribution) {
      map[item.severity] = item.count;
    }
    return [
      { name: "Critical", value: map["Critical"] || 0, color: "#ef4444" },
      { name: "High", value: map["High"] || 0, color: "#fb7185" },
      { name: "Medium", value: map["Medium"] || 0, color: "#fbbf24" },
      { name: "Low", value: map["Low"] || 0, color: "#34d399" },
    ];
  }, [analytics]);

  const attackData = useMemo(() => {
    if (!analytics) return [];
    return analytics.attack_type_frequency.map((item) => ({ name: item.attack_type, value: item.count }));
  }, [analytics]);

  const toolData = useMemo(() => {
    if (!analytics) return [];
    return analytics.tool_distribution.map((item) => ({ name: item.tool, value: item.count }));
  }, [analytics]);

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

  if (!analytics || analytics.total_events === 0) {
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
                {analytics.total_events} events analyzed. Trends will appear as more events are collected.
              </Typography>
            </Box>
          </AnalyticsCard>
        </Grid>

        <Grid size={{ xs: 12, lg: 6 }}>
          <AnalyticsCard title="Device/Target-wise Attacks">
            <Box sx={{ mt: 2 }}>
              {analytics.total_events === 0 ? (
                <Typography variant="body2" color="text.secondary">No target data available.</Typography>
              ) : (
                <Typography variant="body2" color="text.secondary">
                  {analytics.total_events} events collected. Target distribution will be calculated when targets are recorded.
                </Typography>
              )}
            </Box>
          </AnalyticsCard>
        </Grid>

        <Grid size={{ xs: 12, lg: 6 }}>
          <AnalyticsCard title="Country Distribution">
            <Box sx={{ mt: 2 }}>
              <Typography variant="body2" color="text.secondary">
                Country data will appear when geolocation is populated for events.
              </Typography>
            </Box>
          </AnalyticsCard>
        </Grid>
      </Grid>
    </Box>
  );
}

export default AnalyticsPage;
