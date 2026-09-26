import { useEffect, useState } from "react";

import { Box, Chip, Divider, Grid, Stack, Typography } from "@mui/material";

import GlassSurface from "../../components/ui/GlassSurface";
import PageHeader from "../../components/ui/PageHeader/PageHeader";
import { getSecurityEvents } from "./eventsService";

type Severity = "critical" | "high" | "medium" | "low";

interface Recommendation {
  severity: Severity;
  finding: string;
  evidence: string;
  affectedTarget: string;
  tool: string;
  action: string;
  occurrences: number;
}

function AiRecsPage() {
  const [recommendations, setRecommendations] = useState<Recommendation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function loadRecs() {
    try {
      setLoading(true);
      setError(null);
      const events = await getSecurityEvents(200);

      const grouped = new Map<string, Recommendation>();

      for (const event of events) {
        if (!event.attack_type || !event.tool) continue;

        const severity: Severity = (event.severity?.toLowerCase() || "low") as Severity;
        if (!["critical", "high", "medium", "low"].includes(severity)) continue;

        const recommendation: Recommendation = {
          severity,
          finding: event.attack_type,
          evidence: `${event.tool} discovered ${event.attack_type.toLowerCase()}${event.port ? ` on port ${event.port}` : ""}${event.target ? ` targeting ${event.target}` : ""}.`,
          affectedTarget: event.target || event.destination_ip || "Unknown",
          tool: event.tool,
          action: event.recommendation || `Investigate and remediate the ${event.attack_type.toLowerCase()} finding from ${event.tool}.`,
          occurrences: 1,
        };
        const key = `${recommendation.finding}|${recommendation.tool}|${recommendation.affectedTarget}|${recommendation.action}`;
        const existing = grouped.get(key);
        grouped.set(key, existing ? { ...existing, occurrences: existing.occurrences + 1 } : recommendation);
      }

      const priority: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
      const recs = Array.from(grouped.values());
      recs.sort((a, b) => (priority[a.severity] ?? 3) - (priority[b.severity] ?? 3));

      setRecommendations(recs.slice(0, 20));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load recommendations.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadRecs();
  }, []);

  const severityColor = (severity: Severity) => {
    if (severity === "critical") return "#ef4444";
    if (severity === "high") return "#fb7185";
    if (severity === "medium") return "#fbbf24";
    return "#34d399";
  };

  if (loading) {
    return (
      <Box sx={{ minHeight: "calc(100vh - 180px)", pb: { xs: 3, md: 5 } }}>
        <PageHeader title="AI Recs" subtitle="Evidence-based recommendations from current findings." />
        <Box sx={{ display: "flex", justifyContent: "center", alignItems: "center", minHeight: 300 }}>
          <Typography color="text.secondary">Loading recommendations...</Typography>
        </Box>
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ minHeight: "calc(100vh - 180px)", pb: { xs: 3, md: 5 } }}>
        <PageHeader title="AI Recs" subtitle="Evidence-based recommendations from current findings." />
        <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 2, minHeight: 300, justifyContent: "center" }}>
          <Typography color="#fca5a5">{error}</Typography>
        </Box>
      </Box>
    );
  }

  return (
    <Box sx={{ minHeight: "calc(100vh - 180px)", pb: { xs: 3, md: 5 } }}>
      <PageHeader title="AI Recs" subtitle="Evidence-based recommendations derived from actual security findings." />

      {recommendations.length === 0 ? (
        <GlassSurface sx={{ p: 4, textAlign: "center" }}>
          <Typography variant="body1" color="text.secondary" fontWeight={600}>
            No security events available.
          </Typography>
          <Typography variant="body2" color="#6f87a8" sx={{ mt: 1 }}>
            Run a scanner or connect a data source to generate recommendations.
          </Typography>
        </GlassSurface>
      ) : (
        <Grid container spacing={3}>
          {recommendations.map((rec, index) => (
            <Grid size={{ xs: 12, md: 6, lg: 4 }} key={`${rec.finding}-${index}`}>
              <GlassSurface sx={{ p: 3, height: "100%", transition: "border-color 180ms ease, box-shadow 180ms ease", "&:hover": { borderColor: severityColor(rec.severity), boxShadow: `0 0 0 2px ${severityColor(rec.severity)}33` } }}>
                <Stack direction="row" spacing={1} alignItems="center" mb={1.5}>
                  <Chip
                    size="small"
                    label={rec.severity.toUpperCase()}
                    sx={{
                      bgcolor: `${severityColor(rec.severity)}1a`,
                      color: severityColor(rec.severity),
                      border: `1px solid ${severityColor(rec.severity)}33`,
                      fontWeight: 700,
                    }}
                  />
                  <Typography variant="caption" color="text.secondary">{rec.tool}</Typography>
                  {rec.occurrences > 1 && <Chip size="small" label={`${rec.occurrences} occurrences`} variant="outlined" />}
                </Stack>

                <Typography variant="subtitle2" fontWeight={700} gutterBottom>
                  {rec.finding}
                </Typography>

                <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.6, mb: 1.2 }}>
                  {rec.evidence}
                </Typography>

                <Divider sx={{ my: 1.5, borderColor: "rgba(255,255,255,0.08)" }} />

                <Stack spacing={1}>
                  <Box>
                    <Typography variant="caption" sx={{ color: "#7891b2", letterSpacing: 1, fontWeight: 700 }}>
                      AFFECTED TARGET
                    </Typography>
                    <Typography variant="body2" fontWeight={600}>{rec.affectedTarget}</Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" sx={{ color: "#7891b2", letterSpacing: 1, fontWeight: 700 }}>
                      RECOMMENDED ACTION
                    </Typography>
                    <Typography variant="body2" color="text.secondary">{rec.action}</Typography>
                  </Box>
                </Stack>
              </GlassSurface>
            </Grid>
          ))}
        </Grid>
      )}
    </Box>
  );
}

export default AiRecsPage;
