import CheckCircleRoundedIcon from "@mui/icons-material/CheckCircleRounded";

import {
  Avatar,
  Chip,
  LinearProgress,
  List,
  ListItem,
  ListItemAvatar,
  ListItemText,
  Stack,
  Typography,
} from "@mui/material";

import DashboardWidget from "../../../components/ui/DashboardWidget/DashboardWidget";
import detectionService from "../services/detectionService";
import { useEffect, useState } from "react";

function ModelStatus() {
  const [models, setModels] = useState([] as any[]);

  useEffect(() => {
    let mounted = true;
    (async () => {
      try {
        const ms = await detectionService.getModels();
        if (mounted) setModels(ms);
      } catch (e) {
        if (mounted) setModels([]);
      }
    })();
    return () => {
      mounted = false;
    };
  }, []);

  return (
    <DashboardWidget title="AI Model Status" subtitle="Machine learning models deployed" height={420}>
      <List disablePadding>
        {models.map((model) => (
          <ListItem key={model.id} divider disablePadding sx={{ py: 1.5 }}>
            <ListItemAvatar>
              <Avatar sx={{ bgcolor: "#DCFCE7", color: "#16A34A" }}>
                <CheckCircleRoundedIcon />
              </Avatar>
            </ListItemAvatar>

            <ListItemText
              primary={model.name}
              secondary={
                <Stack spacing={1} mt={1}>
                  <Typography variant="caption">{model.algorithm} • {model.version ?? ''}</Typography>

                  <LinearProgress variant="determinate" value={model.accuracy ?? 100} sx={{ height: 8, borderRadius: 8 }} />

                  <Typography variant="caption">Accuracy: {model.accuracy ?? 'N/A'}%</Typography>
                </Stack>
              }
            />

            <Chip label={model.status ?? 'Online'} color="success" size="small" />
          </ListItem>
        ))}
      </List>
    </DashboardWidget>
  );
}

export default ModelStatus;