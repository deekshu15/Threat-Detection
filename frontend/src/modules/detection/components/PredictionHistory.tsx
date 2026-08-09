import { Avatar, Chip, List, ListItem, ListItemAvatar, ListItemText, Typography } from "@mui/material";
import PsychologyRoundedIcon from "@mui/icons-material/PsychologyRounded";
import DashboardWidget from "../../../components/ui/DashboardWidget/DashboardWidget";
import detectionService from "../services/detectionService";
import { useEffect, useState } from "react";

function getSeverityColor(
  severity: string
): "success" | "warning" | "error" {
  switch (severity) {
    case "Critical":
      return "error";

    case "High":
      return "warning";

    default:
      return "success";
  }
}

function PredictionHistory() {
  const [predictions, setPredictions] = useState([] as any[]);

  useEffect(() => {
    let mounted = true;
    (async () => {
      try {
        const data = await detectionService.getPredictions();
        if (mounted) setPredictions(data);
      } catch (e) {
        if (mounted) setPredictions([]);
      }
    })();
    return () => {
      mounted = false;
    };
  }, []);

  return (
    <DashboardWidget title="Prediction History" subtitle="Latest AI predictions" height={450}>
      <List disablePadding>
        {predictions.map((prediction) => (
          <ListItem key={prediction.id} divider disablePadding sx={{ py: 1.5 }}>
            <ListItemAvatar>
              <Avatar sx={{ bgcolor: "#E0F2FE", color: "#0284C7" }}>
                <PsychologyRoundedIcon />
              </Avatar>
            </ListItemAvatar>

            <ListItemText
              primary={prediction.prediction}
              secondary={
                <>
                  <div>{`${prediction.source} • Confidence ${prediction.confidence}% • Model ${prediction.model_name ?? 'unknown'}`}</div>
                  {prediction.top_predictions && prediction.top_predictions.length > 0 && (
                    <div style={{ marginTop: 4, fontSize: 12 }}>
                      Top: {prediction.top_predictions.map((t: any) => `${t.label} (${t.confidence}%)`).join(' • ')}
                    </div>
                  )}
                </>
              }
            />

            <Typography variant="caption" sx={{ mr: 2 }}>
              {prediction.timestamp}
            </Typography>

            <Chip label={prediction.severity} color={getSeverityColor(prediction.severity)} size="small" />
          </ListItem>
        ))}
      </List>
    </DashboardWidget>
  );
}

export default PredictionHistory;