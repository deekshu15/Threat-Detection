import { useEffect, useState } from "react";

import LogoutRoundedIcon from "@mui/icons-material/LogoutRounded";
import NotificationsActiveRoundedIcon from "@mui/icons-material/NotificationsActiveRounded";
import SecurityRoundedIcon from "@mui/icons-material/SecurityRounded";
import StorageRoundedIcon from "@mui/icons-material/StorageRounded";
import { Box, Button, MenuItem, Stack, Switch, TextField, Typography } from "@mui/material";
import { useNavigate } from "react-router-dom";

import { authService } from "../../auth/authService";
import GlassSurface from "../../components/ui/GlassSurface";

type SettingsState = {
  alertNotifications: boolean;
  autoBlockCritical: boolean;
  dataRetentionDays: number;
};

const STORAGE_KEY = "dashboard-settings";

const defaultSettings: SettingsState = {
  alertNotifications: true,
  autoBlockCritical: false,
  dataRetentionDays: 30,
};

function readSettings(): SettingsState {
  try {
    const rawValue = window.localStorage.getItem(STORAGE_KEY);
    if (!rawValue) {
      return defaultSettings;
    }

    const parsed = JSON.parse(rawValue) as Partial<SettingsState>;

    return {
      alertNotifications: typeof parsed.alertNotifications === "boolean" ? parsed.alertNotifications : defaultSettings.alertNotifications,
      autoBlockCritical: typeof parsed.autoBlockCritical === "boolean" ? parsed.autoBlockCritical : defaultSettings.autoBlockCritical,
      dataRetentionDays: typeof parsed.dataRetentionDays === "number" ? parsed.dataRetentionDays : defaultSettings.dataRetentionDays,
    };
  } catch {
    return defaultSettings;
  }
}

function SettingsPage() {
  const navigate = useNavigate();
  const [settings, setSettings] = useState<SettingsState>(defaultSettings);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    setSettings(readSettings());
  }, []);

  useEffect(() => {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
    setSaved(true);
    const timeoutId = window.setTimeout(() => setSaved(false), 1200);
    return () => window.clearTimeout(timeoutId);
  }, [settings]);

  const updateSettings = (patch: Partial<SettingsState>) => {
    setSettings((current) => ({ ...current, ...patch }));
  };

  const handleReset = () => {
    setSettings(defaultSettings);
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(defaultSettings));
  };

  const handleSignOut = async () => {
    window.localStorage.removeItem(STORAGE_KEY);

    try {
      await authService.logout();
    } finally {
      navigate("/sign-in", { replace: true });
    }
  };

  return (
    <Box sx={{ minHeight: "calc(100vh - 180px)", pb: { xs: 3, md: 5 } }}>
      <Box sx={{ width: "100%", maxWidth: 760, mx: "auto", pt: { xs: 1, md: 2 } }}>
        <Typography variant="h4" sx={{ fontWeight: 800, fontSize: { xs: "1.75rem", md: "2rem" } }}>
          Settings &amp; Configuration
        </Typography>
      </Box>

      <GlassSurface
        sx={{
          width: "100%",
          maxWidth: 760,
          mx: "auto",
          mt: 4,
          px: { xs: 2.5, md: 4 },
          py: { xs: 3, md: 3.5 },
          borderRadius: 4,
          background: "rgba(8, 14, 28, 0.82)",
          boxShadow: "0 28px 70px rgba(0, 0, 0, 0.34)",
          transition: "border-color 180ms ease, box-shadow 180ms ease",
          "&:hover": { borderColor: "#22d3ee", boxShadow: "0 0 0 2px rgba(34, 211, 238, 0.18), 0 28px 70px rgba(0, 0, 0, 0.34)" },
        }}
      >
        <Stack spacing={1.4}>
          <Box sx={{ px: 2, py: 1.5, borderRadius: 3, bgcolor: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.05)" }}>
            <Stack direction="row" alignItems="center" justifyContent="space-between" spacing={2}>
              <Stack direction="row" spacing={1.2} alignItems="center">
                <NotificationsActiveRoundedIcon sx={{ color: "#22d3ee" }} fontSize="small" />
                <Typography fontWeight={600}>Alert Notifications</Typography>
              </Stack>

              <Switch
                checked={settings.alertNotifications}
                onChange={(_, checked) => updateSettings({ alertNotifications: checked })}
                inputProps={{ "aria-label": "Alert notifications" }}
              />
            </Stack>
          </Box>

          <Box sx={{ px: 2, py: 1.5, borderRadius: 3, bgcolor: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.05)" }}>
            <Stack direction="row" alignItems="center" justifyContent="space-between" spacing={2}>
              <Stack direction="row" spacing={1.2} alignItems="center">
                <SecurityRoundedIcon sx={{ color: "#facc15" }} fontSize="small" />
                <Typography fontWeight={600}>Auto-block Critical</Typography>
              </Stack>

              <Switch
                checked={settings.autoBlockCritical}
                onChange={(_, checked) => updateSettings({ autoBlockCritical: checked })}
                inputProps={{ "aria-label": "Auto-block critical" }}
              />
            </Stack>
          </Box>

          <Box sx={{ px: 2, py: 1.5, borderRadius: 3, bgcolor: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.05)" }}>
            <Stack direction="row" alignItems="center" justifyContent="space-between" spacing={2}>
              <Stack direction="row" spacing={1.2} alignItems="center">
                <StorageRoundedIcon sx={{ color: "#a855f7" }} fontSize="small" />
                <Typography fontWeight={600}>Data Retention</Typography>
              </Stack>

              <TextField
                select
                size="small"
                value={settings.dataRetentionDays}
                onChange={(event) => updateSettings({ dataRetentionDays: Number(event.target.value) })}
                inputProps={{ "aria-label": "Data retention period" }}
                sx={{ minWidth: 130, "& .MuiOutlinedInput-root": { borderRadius: 2.5 } }}
              >
                {[7, 30, 90, 180, 365].map((days) => (
                  <MenuItem key={days} value={days}>{days} days</MenuItem>
                ))}
              </TextField>
            </Stack>
          </Box>
        </Stack>
      </GlassSurface>

      <Typography variant="caption" sx={{ display: "block", width: "100%", maxWidth: 760, mx: "auto", mt: 1.5, color: saved ? "#34d399" : "text.secondary", textAlign: "right" }}>
        {saved ? "Settings saved" : "Settings are stored for this browser"}
      </Typography>

      <GlassSurface sx={{ width: "100%", maxWidth: 760, mx: "auto", mt: 3, px: { xs: 2.5, md: 4 }, py: { xs: 2.5, md: 3 }, borderRadius: 4, background: "rgba(8, 14, 28, 0.68)", transition: "border-color 180ms ease, box-shadow 180ms ease", "&:hover": { borderColor: "#22d3ee", boxShadow: "0 0 0 2px rgba(34, 211, 238, 0.18)" } }}>
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Data Management
        </Typography>

        <Button
          onClick={handleReset}
          fullWidth
          sx={{
            minHeight: 40,
            borderRadius: 3,
            textTransform: "none",
            fontWeight: 700,
            color: "#e5e7eb",
            bgcolor: "rgba(255,255,255,0.04)",
            border: "1px solid rgba(255,255,255,0.06)",
            "&:hover": { bgcolor: "rgba(255,255,255,0.07)", borderColor: "rgba(255,255,255,0.12)" },
          }}
        >
          Reset Data &amp; Return to Setup
        </Button>
      </GlassSurface>

      <GlassSurface sx={{ width: "100%", maxWidth: 760, mx: "auto", mt: 3, px: { xs: 2.5, md: 4 }, py: { xs: 2.5, md: 3 }, borderRadius: 4, background: "rgba(8, 14, 28, 0.68)", transition: "border-color 180ms ease, box-shadow 180ms ease", "&:hover": { borderColor: "#22d3ee", boxShadow: "0 0 0 2px rgba(34, 211, 238, 0.18)" } }}>
        <Button
          onClick={handleSignOut}
          fullWidth
          startIcon={<LogoutRoundedIcon />}
          sx={{
            minHeight: 40,
            borderRadius: 3,
            textTransform: "none",
            fontWeight: 700,
            color: "#ef4444",
            bgcolor: "transparent",
            border: "1px solid rgba(239, 68, 68, 0.35)",
            "&:hover": { bgcolor: "rgba(239, 68, 68, 0.08)", borderColor: "rgba(239, 68, 68, 0.5)" },
          }}
        >
          Sign Out
        </Button>
      </GlassSurface>
    </Box>
  );
}

export default SettingsPage;
