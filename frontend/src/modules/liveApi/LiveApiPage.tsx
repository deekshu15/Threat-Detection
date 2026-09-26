import { useEffect, useState } from "react";

import PlayArrowOutlinedIcon from "@mui/icons-material/PlayArrowOutlined";
import RadioButtonCheckedOutlinedIcon from "@mui/icons-material/RadioButtonCheckedOutlined";
import StopOutlinedIcon from "@mui/icons-material/StopOutlined";
import WifiOffRoundedIcon from "@mui/icons-material/WifiOffRounded";
import { Box, Button, MenuItem, TextField, Typography } from "@mui/material";

const refreshIntervals = [5, 10, 15, 30];

type ConnectionStatus = "not_configured" | "unverified" | "connected" | "auth_failed" | "connection_failed";

function isHttpEndpoint(value: string) {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function formatTime(date: Date | null) {
  if (!date) {
    return "Waiting for the first refresh";
  }

  return date.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function LiveApiPage() {
  const [endpoint, setEndpoint] = useState("https://api.example.com/threats");
  const [apiKey, setApiKey] = useState("");
  const [refreshInterval, setRefreshInterval] = useState(5);
  const [isStreaming, setIsStreaming] = useState(false);
  const [lastRefreshAt, setLastRefreshAt] = useState<Date | null>(null);
  const [refreshCount, setRefreshCount] = useState(0);
  const [lastResponseStatus, setLastResponseStatus] = useState<number | null>(null);
  const [validationMessage, setValidationMessage] = useState("");
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>("not_configured");

  const verifyConnection = async (): Promise<ConnectionStatus> => {
    const trimmedEndpoint = endpoint.trim();
    const trimmedKey = apiKey.trim();

    if (!trimmedEndpoint || !trimmedKey) {
      return "not_configured";
    }

    if (!isHttpEndpoint(trimmedEndpoint)) {
      setValidationMessage("Enter a valid http or https endpoint.");
      return "connection_failed";
    }

    setValidationMessage("");

    try {
      const controller = new AbortController();
      const timeoutId = window.setTimeout(() => controller.abort(), 10000);

      const response = await fetch(trimmedEndpoint, {
        method: "GET",
        headers: {
          "Authorization": `Bearer ${trimmedKey}`,
          "Accept": "application/json",
        },
        signal: controller.signal,
      });

      window.clearTimeout(timeoutId);
      setLastResponseStatus(response.status);

      if (response.status === 401 || response.status === 403) {
        return "auth_failed";
      }

      if (response.ok) {
        return "connected";
      }

      return "connection_failed";
    } catch {
      return "connection_failed";
    }
  };

  useEffect(() => {
    if (!isStreaming) {
      return undefined;
    }

    const refresh = async () => {
      const status = await verifyConnection();
      setConnectionStatus(status);

      if (status === "connected") {
        setLastRefreshAt(new Date());
        setRefreshCount((count) => count + 1);
        return;
      }

      setIsStreaming(false);
      if (status === "auth_failed") {
        setValidationMessage("Authentication failed. Check your API key.");
      } else {
        setValidationMessage("Connection failed. The endpoint could not be reached.");
      }
    };

    void refresh();
    const intervalId = window.setInterval(() => {
      void refresh();
    }, refreshInterval * 1000);

    return () => {
      window.clearInterval(intervalId);
    };
  }, [isStreaming, refreshInterval]);

  const handleToggleStream = async () => {
    if (isStreaming) {
      setIsStreaming(false);
      setConnectionStatus("not_configured");
      setValidationMessage("");
      return;
    }

    const status = await verifyConnection();
    setConnectionStatus(status);

    if (status === "connected") {
      setIsStreaming(true);
    } else if (status === "not_configured") {
      setValidationMessage("Enter an API endpoint and key before starting the stream.");
    } else if (status === "auth_failed") {
      setValidationMessage("Authentication failed. Check your API key.");
    } else if (status === "connection_failed") {
      setValidationMessage("Connection failed. The endpoint could not be reached.");
    }
  };

  const statusLabel = (() => {
    if (!isStreaming) {
      if (connectionStatus === "auth_failed") return "Authentication Failed";
      if (connectionStatus === "connection_failed") return "Connection Failed";
      if (connectionStatus === "connected") return "Connected";
      if (connectionStatus === "not_configured") return "Not Configured";
      return "Unverified";
    }
    if (connectionStatus === "connected") return "Connected";
    if (connectionStatus === "auth_failed") return "Authentication Failed";
    if (connectionStatus === "connection_failed") return "Connection Failed";
    return "Unverified";
  })();

  const statusColor = (() => {
    if (statusLabel === "Connected") return "#2dd4bf";
    if (statusLabel === "Authentication Failed") return "#fbbf24";
    if (statusLabel === "Connection Failed") return "#f04444";
    if (statusLabel === "Not Configured") return "#6f87a8";
    return "#fbbf24";
  })();

  const statusGlow = (() => {
    if (statusLabel === "Connected") return "rgba(45, 212, 191, 0.28)";
    if (statusLabel === "Authentication Failed") return "rgba(251, 191, 36, 0.28)";
    if (statusLabel === "Connection Failed") return "rgba(240, 68, 68, 0.28)";
    return "rgba(111, 135, 168, 0.28)";
  })();

  const buttonLabel = isStreaming ? "Stop Stream" : "Start Stream";

  return (
    <Box
      sx={{
        minHeight: "calc(100vh - 180px)",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        pt: { xs: 2, md: 4 },
        px: { xs: 2, md: 3 },
        pb: { xs: 4, md: 6 },
      }}
    >
      <Box sx={{ width: "100%", maxWidth: 860, mb: 4 }}>
        <Typography variant="h4" sx={{ fontWeight: 800, fontSize: { xs: "1.7rem", md: "1.95rem" } }}>
          Live API Manager
        </Typography>

        <Typography sx={{ mt: 2, color: "text.secondary", maxWidth: 760, lineHeight: 1.7, fontSize: { xs: "0.96rem", md: "1.02rem" } }}>
          Connect to live threat intelligence API feeds for real-time data streaming.
        </Typography>
      </Box>

      <Box
        sx={{
          width: "100%",
          maxWidth: 860,
          borderRadius: 4,
          border: "1px solid rgba(255,255,255,0.08)",
          bgcolor: "rgba(8, 14, 28, 0.76)",
          boxShadow: "0 30px 70px rgba(0, 0, 0, 0.32)",
          transition: "border-color 180ms ease, box-shadow 180ms ease",
          "&:hover": {
            borderColor: "#22d3ee",
            boxShadow: "0 0 0 2px rgba(34, 211, 238, 0.18), 0 30px 70px rgba(0, 0, 0, 0.32)",
          },
          backdropFilter: "blur(18px)",
          WebkitBackdropFilter: "blur(18px)",
          px: { xs: 2.5, md: 4 },
          py: { xs: 3, md: 3.5 },
        }}
      >
        <Box sx={{ display: "grid", gap: 2.5 }}>
          <Box>
            <Typography variant="caption" sx={{ display: "block", mb: 1.2, letterSpacing: 1, color: "#6f87a8" }}>
              API ENDPOINT
            </Typography>
            <TextField
              fullWidth
              hiddenLabel
              value={endpoint}
              onChange={(event) => {
                setEndpoint(event.target.value);
                if (validationMessage) {
                  setValidationMessage("");
                }
              }}
              placeholder="https://api.example.com/threats"
              variant="outlined"
              size="small"
              sx={{
                "& .MuiOutlinedInput-root": {
                  borderRadius: 3,
                  bgcolor: "rgba(255,255,255,0.035)",
                  color: "text.primary",
                  fontSize: "0.95rem",
                  minHeight: 44,
                  "& fieldset": {
                    borderColor: "rgba(255,255,255,0.04)",
                  },
                  "&:hover fieldset": {
                    borderColor: "rgba(255,255,255,0.12)",
                  },
                  "&.Mui-focused fieldset": {
                    borderColor: "rgba(19, 216, 255, 0.45)",
                  },
                },
                "& .MuiInputBase-input": {
                  py: 1.6,
                  px: 2,
                  fontWeight: 500,
                  "&::placeholder": {
                    color: "rgba(148, 163, 184, 0.78)",
                    opacity: 1,
                  },
                },
              }}
            />
          </Box>

          <Box>
            <Typography variant="caption" sx={{ display: "block", mb: 1.2, letterSpacing: 1, color: "#6f87a8" }}>
              API KEY
            </Typography>
            <TextField
              fullWidth
              hiddenLabel
              value={apiKey}
              onChange={(event) => {
                setApiKey(event.target.value);
                if (validationMessage) {
                  setValidationMessage("");
                }
              }}
              placeholder="Enter API key..."
              variant="outlined"
              size="small"
              type="password"
              sx={{
                "& .MuiOutlinedInput-root": {
                  borderRadius: 3,
                  bgcolor: "rgba(255,255,255,0.035)",
                  color: "text.primary",
                  fontSize: "0.95rem",
                  minHeight: 44,
                  "& fieldset": {
                    borderColor: "rgba(255,255,255,0.04)",
                  },
                  "&:hover fieldset": {
                    borderColor: "rgba(255,255,255,0.12)",
                  },
                  "&.Mui-focused fieldset": {
                    borderColor: "rgba(19, 216, 255, 0.45)",
                  },
                },
                "& .MuiInputBase-input": {
                  py: 1.6,
                  px: 2,
                  fontWeight: 500,
                  "&::placeholder": {
                    color: "rgba(148, 163, 184, 0.78)",
                    opacity: 1,
                  },
                },
              }}
            />
          </Box>

          <Box>
            <Typography variant="caption" sx={{ display: "block", mb: 1.2, letterSpacing: 1, color: "#6f87a8" }}>
              REFRESH INTERVAL
            </Typography>
            <TextField
              select
              fullWidth
              hiddenLabel
              value={refreshInterval}
              onChange={(event) => setRefreshInterval(Number(event.target.value))}
              variant="outlined"
              size="small"
              sx={{
                "& .MuiOutlinedInput-root": {
                  borderRadius: 3,
                  bgcolor: "rgba(255,255,255,0.035)",
                  color: "text.primary",
                  fontSize: "0.95rem",
                  minHeight: 44,
                  "& fieldset": {
                    borderColor: "rgba(255,255,255,0.04)",
                  },
                  "&:hover fieldset": {
                    borderColor: "rgba(255,255,255,0.12)",
                  },
                  "&.Mui-focused fieldset": {
                    borderColor: "rgba(19, 216, 255, 0.45)",
                  },
                },
                "& .MuiSelect-select": {
                  py: 1.6,
                  px: 2,
                  fontWeight: 500,
                },
              }}
            >
              {refreshIntervals.map((interval) => (
                <MenuItem key={interval} value={interval}>
                  {interval} seconds
                </MenuItem>
              ))}
            </TextField>
          </Box>

          <Button
            fullWidth
            onClick={handleToggleStream}
            startIcon={isStreaming ? <StopOutlinedIcon /> : <PlayArrowOutlinedIcon />}
            sx={{
              minHeight: 42,
              borderRadius: 999,
              mt: 0.5,
              textTransform: "none",
              fontSize: "1rem",
              fontWeight: 700,
              color: "#e7edf6",
              border: "1px solid rgba(255,255,255,0.06)",
              background: isStreaming
                ? "linear-gradient(180deg, rgba(45, 212, 191, 0.14), rgba(15, 23, 42, 0.92))"
                : "linear-gradient(180deg, rgba(255,255,255,0.03), rgba(15, 23, 42, 0.96))",
              boxShadow: "none",
              "&:hover": {
                background: isStreaming
                  ? "linear-gradient(180deg, rgba(45, 212, 191, 0.18), rgba(15, 23, 42, 0.92))"
                  : "linear-gradient(180deg, rgba(255,255,255,0.05), rgba(15, 23, 42, 0.98))",
                boxShadow: "none",
              },
            }}
          >
            {buttonLabel}
          </Button>

          {validationMessage && (
            <Typography variant="body2" sx={{ color: "#fca5a5", mt: -0.5 }}>
              {validationMessage}
            </Typography>
          )}

          <Box sx={{ display: "flex", alignItems: "center", gap: 1.2, pt: 0.5 }}>
            <Box
              sx={{
                width: 10,
                height: 10,
                borderRadius: "50%",
                bgcolor: statusColor,
                boxShadow: `0 0 0 5px ${statusGlow}`,
                flexShrink: 0,
              }}
            />
            <Box>
              <Typography variant="body2" sx={{ color: isStreaming ? "#9fe9de" : "#9fb5d1", fontWeight: 500 }}>
                {statusLabel}
              </Typography>
              <Typography variant="caption" sx={{ display: "block", mt: 0.4, color: "text.secondary" }}>
                {isStreaming
                  ? `Checked every ${refreshInterval} seconds. Last check at ${formatTime(lastRefreshAt)}. ${refreshCount} check${refreshCount === 1 ? "" : "s"} completed${lastResponseStatus ? ` (HTTP ${lastResponseStatus})` : ""}.`
                  : "Stream is idle until you start it."}
              </Typography>
            </Box>

            <Box sx={{ ml: "auto", color: isStreaming ? "#9fe9de" : "#9fb5d1", display: "flex", alignItems: "center", gap: 0.75 }}>
              {isStreaming && statusLabel === "Connected" ? <RadioButtonCheckedOutlinedIcon sx={{ fontSize: 18 }} /> : <WifiOffRoundedIcon sx={{ fontSize: 18 }} />}
            </Box>
          </Box>
        </Box>
      </Box>
    </Box>
  );
}

export default LiveApiPage;
