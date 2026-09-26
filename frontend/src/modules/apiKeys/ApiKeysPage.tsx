import { useEffect, useMemo, useState } from "react";

import AddRoundedIcon from "@mui/icons-material/AddRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import KeyRoundedIcon from "@mui/icons-material/KeyRounded";
import PowerSettingsNewRoundedIcon from "@mui/icons-material/PowerSettingsNewRounded";
import { Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle, IconButton, Stack, TextField, Typography } from "@mui/material";

import GlassSurface from "../../components/ui/GlassSurface";

type ApiKeyItem = {
  id: string;
  name: string;
  provider: string;
  masked_key: string;
  active: boolean;
};

type ApiKeyFormState = {
  name: string;
  provider: string;
  key: string;
};

const emptyForm: ApiKeyFormState = {
  name: "",
  provider: "",
  key: "",
};

const API_BASE = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

function ApiKeysPage() {
  const [items, setItems] = useState<ApiKeyItem[]>([]);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [form, setForm] = useState<ApiKeyFormState>(emptyForm);
  const [error, setError] = useState("");

  useEffect(() => {
    fetch(`${API_BASE}/api/keys`)
      .then(async (response) => {
        if (!response.ok) throw new Error("Unable to load API keys.");
        return response.json() as Promise<{ keys: ApiKeyItem[] }>;
      })
      .then((data) => setItems(data.keys))
      .catch((loadError) => setError(loadError instanceof Error ? loadError.message : "Unable to load API keys."));
  }, []);

  const activeCount = useMemo(() => items.filter((item) => item.active).length, [items]);

  const handleAddKey = async () => {
    if (!form.name.trim() || !form.provider.trim() || !form.key.trim()) {
      return;
    }

    try {
      const response = await fetch(`${API_BASE}/api/keys`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      if (!response.ok) throw new Error("Unable to save API key.");
      const nextItem = (await response.json()) as ApiKeyItem;
      setItems((current) => [nextItem, ...current]);
      setForm(emptyForm);
      setDialogOpen(false);
    } catch (addError) {
      setError(addError instanceof Error ? addError.message : "Unable to save API key.");
    }
  };

  const toggleActive = async (item: ApiKeyItem) => {
    const response = await fetch(`${API_BASE}/api/keys/${item.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ active: !item.active }),
    });
    if (!response.ok) {
      setError("Unable to update API key.");
      return;
    }
    const updated = (await response.json()) as ApiKeyItem;
    setItems((current) => current.map((currentItem) => (currentItem.id === updated.id ? updated : currentItem)));
  };

  const removeKey = async (id: string) => {
    const response = await fetch(`${API_BASE}/api/keys/${id}`, { method: "DELETE" });
    if (!response.ok) {
      setError("Unable to revoke API key.");
      return;
    }
    setItems((current) => current.filter((item) => item.id !== id));
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
      <Box sx={{ width: "100%", maxWidth: 1120, mx: "auto" }}>
        <Stack direction="row" alignItems="flex-start" justifyContent="space-between" spacing={2} sx={{ mb: 3.5 }}>
          <Box>
            <Stack direction="row" spacing={1.2} alignItems="center">
              <Box
                sx={{
                  width: 28,
                  height: 28,
                  borderRadius: "50%",
                  display: "inline-flex",
                  alignItems: "center",
                  justifyContent: "center",
                  color: "#22d3ee",
                  bgcolor: "rgba(34, 211, 238, 0.08)",
                  border: "1px solid rgba(34, 211, 238, 0.22)",
                }}
              >
                <KeyRoundedIcon sx={{ fontSize: 18 }} />
              </Box>
              <Typography variant="h4" sx={{ fontWeight: 800, fontSize: { xs: "1.8rem", md: "2.05rem" } }}>
                API Key <Box component="span" sx={{ color: "#22d3ee" }}>Management</Box>
              </Typography>
            </Stack>
            <Typography sx={{ mt: 1.1, color: "text.secondary", fontSize: { xs: "0.98rem", md: "1.04rem" } }}>
              Manage API keys for threat intelligence feeds and integrations.
            </Typography>
          </Box>

          <Button
            onClick={() => setDialogOpen(true)}
            startIcon={<AddRoundedIcon />}
            sx={{
              minWidth: 132,
              minHeight: 40,
              borderRadius: 999,
              textTransform: "none",
              fontWeight: 700,
              color: "#e5e7eb",
              bgcolor: "rgba(255,255,255,0.03)",
              border: "1px solid rgba(255,255,255,0.06)",
              "&:hover": {
                bgcolor: "rgba(255,255,255,0.06)",
                borderColor: "rgba(255,255,255,0.12)",
              },
            }}
          >
            Add Key
          </Button>
        </Stack>

        {error && (
          <Typography sx={{ mt: 2, color: "#fca5a5" }}>
            {error}
          </Typography>
        )}

        <Stack spacing={1.6}>
          {items.map((item) => (
            <GlassSurface
              key={item.id}
              sx={{
                px: { xs: 2.2, md: 3 },
                py: { xs: 2.2, md: 2.4 },
                borderRadius: 4,
                background: "rgba(8, 14, 28, 0.78)",
                border: "1px solid rgba(255,255,255,0.06)",
                boxShadow: "0 18px 50px rgba(0, 0, 0, 0.28)",
              }}
            >
              <Stack direction="row" alignItems="center" justifyContent="space-between" spacing={2}>
                <Stack direction="row" spacing={2} alignItems="center" sx={{ minWidth: 0 }}>
                  <Box
                    sx={{
                      width: 10,
                      height: 10,
                      borderRadius: "50%",
                      bgcolor: item.active ? "#22c55e" : "#ef4444",
                      boxShadow: item.active ? "0 0 0 6px rgba(34, 197, 94, 0.08)" : "0 0 0 6px rgba(239, 68, 68, 0.08)",
                      flexShrink: 0,
                    }}
                  />

                  <Box sx={{ minWidth: 0 }}>
                    <Stack direction="row" spacing={1.2} alignItems="center" sx={{ minWidth: 0 }}>
                      <Typography sx={{ fontSize: { xs: "1.02rem", md: "1.08rem" }, fontWeight: 800, lineHeight: 1.1 }} noWrap>
                        {item.name}
                      </Typography>
                      <Chip
                        label={item.provider}
                        size="small"
                        sx={{
                          height: 28,
                          borderRadius: 999,
                          bgcolor: "rgba(34, 211, 238, 0.08)",
                          color: "#22d3ee",
                          border: "1px solid rgba(34, 211, 238, 0.28)",
                          fontWeight: 700,
                          maxWidth: 160,
                          "& .MuiChip-label": {
                            px: 1.2,
                          },
                        }}
                      />
                    </Stack>
                    <Typography
                      sx={{
                        mt: 0.6,
                        color: "#8ea3bf",
                        fontSize: { xs: "0.92rem", md: "0.98rem" },
                        letterSpacing: 0.2,
                        wordBreak: "break-all",
                      }}
                    >
                      {item.masked_key}
                    </Typography>
                  </Box>
                </Stack>

                <Stack direction="row" spacing={1} alignItems="center" flexShrink={0}>
                  <IconButton
                    onClick={() => void toggleActive(item)}
                    sx={{
                      width: 40,
                      height: 40,
                      borderRadius: 3,
                      color: item.active ? "#22c55e" : "#ef4444",
                      bgcolor: "rgba(255,255,255,0.03)",
                      border: "1px solid rgba(255,255,255,0.05)",
                      "&:hover": {
                        bgcolor: "rgba(255,255,255,0.06)",
                      },
                    }}
                    aria-label={item.active ? "Deactivate API key" : "Activate API key"}
                  >
                    <PowerSettingsNewRoundedIcon fontSize="small" />
                  </IconButton>

                  <IconButton
                    onClick={() => removeKey(item.id)}
                    sx={{
                      width: 40,
                      height: 40,
                      borderRadius: 3,
                      color: "#f87171",
                      bgcolor: "rgba(255,255,255,0.03)",
                      border: "1px solid rgba(255,255,255,0.05)",
                      "&:hover": {
                        bgcolor: "rgba(255, 76, 76, 0.10)",
                        borderColor: "rgba(248, 113, 113, 0.28)",
                      },
                    }}
                    aria-label="Delete API key"
                  >
                    <DeleteOutlineRoundedIcon fontSize="small" />
                  </IconButton>
                </Stack>
              </Stack>
            </GlassSurface>
          ))}
        </Stack>

        <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} fullWidth maxWidth="sm">
          <DialogTitle sx={{ fontWeight: 800 }}>Add API Key</DialogTitle>
          <DialogContent sx={{ pt: 1, display: "grid", gap: 2 }}>
            <TextField
              label="Name"
              value={form.name}
              onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))}
              fullWidth
              autoFocus
            />
            <TextField
              label="Provider"
              value={form.provider}
              onChange={(event) => setForm((current) => ({ ...current, provider: event.target.value }))}
              fullWidth
            />
            <TextField
              label="API Key"
              value={form.key}
              onChange={(event) => setForm((current) => ({ ...current, key: event.target.value }))}
              fullWidth
              multiline
              minRows={3}
            />
          </DialogContent>
          <DialogActions sx={{ px: 3, pb: 2.5 }}>
            <Button onClick={() => setDialogOpen(false)} sx={{ textTransform: "none" }}>
              Cancel
            </Button>
            <Button
              onClick={handleAddKey}
              variant="contained"
              sx={{ textTransform: "none", fontWeight: 700 }}
              disabled={!form.name.trim() || !form.provider.trim() || !form.key.trim()}
            >
              Add Key
            </Button>
          </DialogActions>
        </Dialog>
      </Box>
    </Box>
  );
}

export default ApiKeysPage;
