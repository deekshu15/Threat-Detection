import { useState } from "react";

import BookOutlinedIcon from "@mui/icons-material/BookOutlined";
import PlayArrowOutlinedIcon from "@mui/icons-material/PlayArrowOutlined";
import PowerOffRoundedIcon from "@mui/icons-material/PowerOffRounded";
import SecurityRoundedIcon from "@mui/icons-material/SecurityRounded";
import TuneRoundedIcon from "@mui/icons-material/TuneRounded";
import { Box, Button, Dialog, DialogActions, DialogContent, DialogTitle, Stack, TextField, Typography } from "@mui/material";

import GlassSurface from "../../components/ui/GlassSurface";

const API_BASE = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

type ToolControlPageProps = {
  title: string;
  description: string;
  category: string;
  docsUrl: string;
  ready?: boolean;
};

function ToolControlPage({ title, description, category, docsUrl, ready = false }: ToolControlPageProps) {
  const [isConfigured, setIsConfigured] = useState(ready);
  const [isRunning, setIsRunning] = useState(false);
  const [configureOpen, setConfigureOpen] = useState(false);
  const [target, setTarget] = useState("");
  const [message, setMessage] = useState("");

  const status = isRunning ? "Running" : isConfigured ? "Ready" : "Not Connected";
  const isReady = isConfigured || isRunning;

  const handleRun = async () => {
    if (!isConfigured) {
      setMessage("Configure this tool before checking its connection.");
      return;
    }

    setIsRunning(true);
    setMessage(`Checking ${title}${target ? ` for ${target}` : ""}...`);

    try {
      const response = await fetch(`${API_BASE}/api/tools/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tool: title, target }),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(payload.detail || `${title} could not be checked.`);
      }

      setMessage(`${title} is available. ${payload.version}`);
    } catch (error) {
      setIsConfigured(false);
      setMessage(error instanceof Error ? error.message : `${title} could not be checked.`);
    } finally {
      setIsRunning(false);
    }
  };

  const saveConfiguration = () => {
    setIsConfigured(true);
    setConfigureOpen(false);
    setMessage("Configuration saved. Run a connection check to verify the local tool.");
  };

  return (
    <Box sx={{ minHeight: "calc(100vh - 180px)", px: { xs: 0, md: 1 }, pb: { xs: 3, md: 5 } }}>
      <GlassSurface
        sx={{
          width: "100%",
          maxWidth: 840,
          mx: "auto",
          mt: { xs: 1, md: 2 },
          p: { xs: 3, md: 3.75 },
          borderRadius: 3,
          background: "rgba(8, 14, 28, 0.78)",
          boxShadow: "0 28px 70px rgba(0, 0, 0, 0.28)",
          transition: "border-color 180ms ease, box-shadow 180ms ease",
          "&:hover": {
            borderColor: "#22d3ee",
            boxShadow: "0 0 0 2px rgba(34, 211, 238, 0.18), 0 28px 70px rgba(0, 0, 0, 0.28)",
          },
        }}
      >
        <Stack direction="row" justifyContent="space-between" alignItems="flex-start" spacing={2}>
          <Typography variant="h6" sx={{ fontWeight: 800, fontSize: "1.05rem" }}>
            {title}
          </Typography>

          <Box sx={{ display: "inline-flex", alignItems: "center", gap: 0.65, px: 1.35, py: 0.55, borderRadius: 999, color: isReady ? "#0b1722" : "#f04444", bgcolor: isReady ? "#16d7f3" : "transparent", border: isReady ? "none" : "1px solid rgba(240, 68, 68, 0.7)", whiteSpace: "nowrap" }}>
            {isReady ? <SecurityRoundedIcon sx={{ fontSize: 15 }} /> : <PowerOffRoundedIcon sx={{ fontSize: 15 }} />}
            <Typography sx={{ fontSize: "0.8rem", fontWeight: 700 }}>{status}</Typography>
          </Box>
        </Stack>

        <Typography sx={{ mt: 3, color: "#7891b2", fontSize: "0.94rem" }}>{description}</Typography>
        <Typography variant="caption" sx={{ display: "block", mt: 3, color: "#7891b2", letterSpacing: 0.35, fontWeight: 700 }}>
          CATEGORY: {category.toUpperCase()}
        </Typography>

        <Stack spacing={1.15} sx={{ mt: 5.5 }}>
          <Button onClick={handleRun} disabled={isRunning} startIcon={<PlayArrowOutlinedIcon />} sx={actionButtonSx}>
            {isRunning ? "Running Scan" : "Run Scan"}
          </Button>
          <Button onClick={() => window.open(docsUrl, "_blank", "noopener,noreferrer")} startIcon={<BookOutlinedIcon />} sx={actionButtonSx}>
            View Docs
          </Button>
          <Button onClick={() => setConfigureOpen(true)} startIcon={<TuneRoundedIcon />} sx={actionButtonSx}>
            Configure
          </Button>
        </Stack>

        {message && <Typography sx={{ mt: 2, color: "#8fa3bd", fontSize: "0.86rem" }}>{message}</Typography>}
      </GlassSurface>

      <Dialog open={configureOpen} onClose={() => setConfigureOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle sx={{ fontWeight: 800 }}>Configure {title}</DialogTitle>
        <DialogContent sx={{ pt: 1 }}>
          <TextField autoFocus fullWidth label="Target or connection" value={target} onChange={(event) => setTarget(event.target.value)} placeholder="Enter a target or connection name" />
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2.5 }}>
          <Button onClick={() => setConfigureOpen(false)}>Cancel</Button>
          <Button onClick={saveConfiguration} variant="contained">Save</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

const actionButtonSx = {
  minHeight: 41,
  borderRadius: 2.5,
  color: "#dce4ef",
  bgcolor: "rgba(33, 43, 59, 0.52)",
  border: "1px solid rgba(255,255,255,0.045)",
  "&:hover": { bgcolor: "rgba(48, 62, 82, 0.62)", borderColor: "rgba(34, 211, 238, 0.18)" },
};

export default ToolControlPage;
