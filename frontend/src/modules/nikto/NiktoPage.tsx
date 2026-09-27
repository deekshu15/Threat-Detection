import { useEffect, useMemo, useState } from "react";

import BookOutlinedIcon from "@mui/icons-material/BookOutlined";
import PlayArrowOutlinedIcon from "@mui/icons-material/PlayArrowOutlined";
import PowerOffRoundedIcon from "@mui/icons-material/PowerOffRounded";
import TuneRoundedIcon from "@mui/icons-material/TuneRounded";
import { Box, Button, Dialog, DialogActions, DialogContent, DialogTitle, Stack, TextField, Typography } from "@mui/material";

import GlassSurface from "../../components/ui/GlassSurface";

type NiktoConfig = {
  target: string;
  port: string;
  userAgent: string;
};

type ScanState = "disconnected" | "connected" | "scanning";

const STORAGE_KEY = "dashboard-nikto-config";
const DOCS_URL = "https://github.com/sullo/nikto";
const API_BASE = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

const defaultConfig: NiktoConfig = {
  target: "https://example.com",
  port: "80,443",
  userAgent: "Mozilla/5.0 (Nikto Dashboard)",
};

function readConfig(): NiktoConfig {
  try {
    const rawValue = window.localStorage.getItem(STORAGE_KEY);
    if (!rawValue) {
      return defaultConfig;
    }

    const parsed = JSON.parse(rawValue) as Partial<NiktoConfig>;

    return {
      target: typeof parsed.target === "string" && parsed.target.trim() ? parsed.target : defaultConfig.target,
      port: typeof parsed.port === "string" && parsed.port.trim() ? parsed.port : defaultConfig.port,
      userAgent: typeof parsed.userAgent === "string" && parsed.userAgent.trim() ? parsed.userAgent : defaultConfig.userAgent,
    };
  } catch {
    return defaultConfig;
  }
}

function NiktoPage() {
  const [config, setConfig] = useState<NiktoConfig>(defaultConfig);
  const [draft, setDraft] = useState<NiktoConfig>(defaultConfig);
  const [configOpen, setConfigOpen] = useState(false);
  const [scanState, setScanState] = useState<ScanState>("disconnected");
  const [scanMessage, setScanMessage] = useState("Ready to scan the current target.");

  useEffect(() => {
    const storedConfig = readConfig();
    setConfig(storedConfig);
    setDraft(storedConfig);
  }, []);

  useEffect(() => {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(config));
  }, [config]);

  const statusLabel = useMemo(() => {
    if (scanState === "scanning") {
      return "Scanning";
    }

    if (scanState === "connected") {
      return "Connected";
    }

    return "Not Configured";
  }, [scanState]);

  const handleRunScan = async () => {
    setScanState("scanning");
    setScanMessage(`Starting Nikto scan for ${config.target}...`);

    try {
      const response = await fetch(`${API_BASE}/api/nikto/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: config.target,
          port: config.port,
          user_agent: config.userAgent,
        }),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(payload.detail || "Nikto scan could not be started.");
      }

      setScanState("connected");
      setScanMessage(`Nikto scan completed for ${config.target}. ${payload.output?.split("\n")[0] || "Results received from the backend."}`);
    } catch (error) {
      setScanState("disconnected");
      setScanMessage(error instanceof Error ? error.message : "Nikto scan could not be started.");
    }
  };

  const handleOpenDocs = () => {
    window.open(DOCS_URL, "_blank", "noopener,noreferrer");
  };

  const handleConfigure = () => {
    setDraft(config);
    setConfigOpen(true);
  };

  const handleSaveConfig = () => {
    setConfig(draft);
    setConfigOpen(false);
    setScanMessage(`Configuration saved for ${draft.target}. Nikto is ready to scan.`);
  };

  return (
    <Box
      sx={{
        minHeight: "calc(100vh - 180px)",
        px: { xs: 2, md: 3 },
        pt: { xs: 1, md: 2 },
        pb: { xs: 4, md: 6 },
      }}
    >
      <GlassSurface
        sx={{
          width: "100%",
          maxWidth: 840,
          mx: "auto",
          mt: 0.5,
          px: { xs: 2.5, md: 4.5 },
          py: { xs: 2.8, md: 4 },
          borderRadius: 4,
          background: "rgba(8, 14, 28, 0.84)",
          boxShadow: "0 30px 72px rgba(0, 0, 0, 0.34), inset 0 0 0 1px rgba(34, 211, 238, 0.06)",
          transition: "border-color 180ms ease, box-shadow 180ms ease",
          "&:hover": {
            borderColor: "#22d3ee",
            boxShadow: "0 0 0 2px rgba(34, 211, 238, 0.18), 0 30px 72px rgba(0, 0, 0, 0.34)",
          },
        }}
      >
        <Box sx={{ mb: 2.6 }}>
          <Stack direction="row" alignItems="center" spacing={1.4}>
            <Typography variant="h4" sx={{ fontWeight: 800, fontSize: { xs: "1.72rem", md: "1.9rem" } }}>
              Nikto
            </Typography>
            <Box
              sx={{
                display: "inline-flex",
                alignItems: "center",
                gap: 0.5,
                px: 1.05,
                py: 0.3,
                borderRadius: 999,
                border: "1px solid rgba(239, 68, 68, 0.55)",
                color: "#f87171",
                bgcolor: "rgba(239, 68, 68, 0.04)",
                whiteSpace: "nowrap",
              }}
            >
              <PowerOffRoundedIcon sx={{ fontSize: 13 }} />
              <Typography sx={{ fontSize: "0.75rem", fontWeight: 700, lineHeight: 1 }}>{statusLabel}</Typography>
            </Box>
          </Stack>
          <Box>
            <Typography sx={{ mt: 2, color: "text.secondary", fontSize: { xs: "0.98rem", md: "1.02rem" } }}>
              Web server vulnerability scanner.
            </Typography>
          </Box>
        </Box>

        <Typography variant="caption" sx={{ display: "block", color: "#7c8ba3", letterSpacing: 1, fontWeight: 700 }}>
          CATEGORY: VULNERABILITY ASSESSMENT
        </Typography>

        <Stack spacing={1.2} sx={{ mt: 4.2 }}>
          <Button
            onClick={handleRunScan}
            disabled={scanState === "scanning"}
            startIcon={<PlayArrowOutlinedIcon />}
            sx={{
              minHeight: 40,
              borderRadius: 3,
              textTransform: "none",
              fontWeight: 700,
              color: "#e5e7eb",
              bgcolor: "rgba(255,255,255,0.04)",
              border: "1px solid rgba(255,255,255,0.05)",
              "&:hover": {
                bgcolor: "rgba(255,255,255,0.07)",
                borderColor: "rgba(255,255,255,0.12)",
              },
            }}
          >
            {scanState === "scanning" ? "Running Scan" : "Run Scan"}
          </Button>

          <Button
            onClick={handleOpenDocs}
            startIcon={<BookOutlinedIcon />}
            sx={{
              minHeight: 40,
              borderRadius: 3,
              textTransform: "none",
              fontWeight: 700,
              color: "#e5e7eb",
              bgcolor: "rgba(255,255,255,0.04)",
              border: "1px solid rgba(255,255,255,0.05)",
              "&:hover": {
                bgcolor: "rgba(255,255,255,0.07)",
                borderColor: "rgba(255,255,255,0.12)",
              },
            }}
          >
            View Docs
          </Button>

          <Button
            onClick={handleConfigure}
            startIcon={<TuneRoundedIcon />}
            sx={{
              minHeight: 40,
              borderRadius: 3,
              textTransform: "none",
              fontWeight: 700,
              color: "#e5e7eb",
              bgcolor: "rgba(255,255,255,0.04)",
              border: "1px solid rgba(255,255,255,0.05)",
              "&:hover": {
                bgcolor: "rgba(255,255,255,0.07)",
                borderColor: "rgba(255,255,255,0.12)",
              },
            }}
          >
            Configure
          </Button>
        </Stack>

        <Typography sx={{ mt: 2.4, color: "#8fa3bd", fontSize: "0.92rem" }}>{scanMessage}</Typography>
      </GlassSurface>

      <Dialog open={configOpen} onClose={() => setConfigOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle sx={{ fontWeight: 800 }}>Configure Nikto</DialogTitle>
        <DialogContent sx={{ pt: 1, display: "grid", gap: 2 }}>
          <TextField
            label="Target"
            value={draft.target}
            onChange={(event) => setDraft((current) => ({ ...current, target: event.target.value }))}
            fullWidth
          />
          <TextField
            label="Ports"
            value={draft.port}
            onChange={(event) => setDraft((current) => ({ ...current, port: event.target.value }))}
            fullWidth
          />
          <TextField
            label="User Agent"
            value={draft.userAgent}
            onChange={(event) => setDraft((current) => ({ ...current, userAgent: event.target.value }))}
            fullWidth
          />
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2.5 }}>
          <Button onClick={() => setConfigOpen(false)} sx={{ textTransform: "none" }}>
            Cancel
          </Button>
          <Button onClick={handleSaveConfig} variant="contained" sx={{ textTransform: "none", fontWeight: 700 }}>
            Save
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default NiktoPage;
