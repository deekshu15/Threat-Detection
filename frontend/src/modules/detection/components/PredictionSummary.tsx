import PsychologyRoundedIcon from "@mui/icons-material/PsychologyRounded";
import ReportProblemRoundedIcon from "@mui/icons-material/ReportProblemRounded";
import VerifiedRoundedIcon from "@mui/icons-material/VerifiedRounded";
import BugReportRoundedIcon from "@mui/icons-material/BugReportRounded";

import Grid from "@mui/material/Grid";
import { useState, useEffect } from "react";

import { StatusCard } from "../../../components/ui/StatusCard";

function PredictionSummary() {
  const [summary, setSummary] = useState<any>(null);

  useEffect(() => {
    let mounted = true;
    (async () => {
      try {
        const s = await (await import('../services/detectionService')).default.getSummary();
        if (mounted) setSummary(s);
      } catch (e) {
        if (mounted) setSummary(null);
      }
    })();
    return () => { mounted = false };
  }, []);

  const threats = summary?.threatsDetected ?? 'N/A';
  const confidence = summary?.confidence ? `${Math.round(summary.confidence * 100)}%` : 'N/A';
  const top = summary?.top_prediction ? `${summary.top_prediction.label} (${Math.round((summary.top_prediction.confidence ?? 0)*100)}%)` : 'N/A';

  return (
    <Grid container spacing={3}>
      <Grid size={{ xs: 12, md: 6, xl: 3 }}>
        <StatusCard title="Threats Detected" value={String(threats)} trend={0} subtitle="AI identified" icon={<BugReportRoundedIcon />} color="#DC2626" />
      </Grid>

      <Grid size={{ xs: 12, md: 6, xl: 3 }}>
        <StatusCard title="Anomalies" value={'N/A'} trend={0} subtitle="Isolation Forest" icon={<PsychologyRoundedIcon />} color="#1D4ED8" />
      </Grid>

      <Grid size={{ xs: 12, md: 6, xl: 3 }}>
        <StatusCard title="False Positives" value={'N/A'} trend={0} subtitle="Lower is better" icon={<ReportProblemRoundedIcon />} color="#F59E0B" />
      </Grid>

      <Grid size={{ xs: 12, md: 6, xl: 3 }}>
        <StatusCard title="Confidence" value={confidence} trend={0} subtitle={top} icon={<VerifiedRoundedIcon />} color="#10B981" />
      </Grid>
    </Grid>
  );
}

export default PredictionSummary;