import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Box, Button, Paper, Stack, TextField, Typography, Alert } from "@mui/material";
import ShieldRoundedIcon from "@mui/icons-material/ShieldRounded";

import { authService } from "../auth/authService";

function SignInPage() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      await authService.login(email, password);
      navigate("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign in failed. Check your credentials.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box
      sx={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        bgcolor: "#0B0F14",
        backgroundImage: "radial-gradient(circle at top left, rgba(79, 93, 255, 0.18), transparent 22%), linear-gradient(135deg, #0b0f14 0%, #10151c 100%)",
        p: 2,
      }}
    >
      <Paper
        elevation={0}
        sx={{
          p: { xs: 3, sm: 4.5 },
          width: "100%",
          maxWidth: 480,
          borderRadius: 4,
          border: "1px solid rgba(255,255,255,0.12)",
          bgcolor: "rgba(255,255,255,0.05)",
          backdropFilter: "blur(16px)",
        }}
      >
        <Stack spacing={1.2} alignItems="center" mb={{ xs: 3, sm: 3.5 }}>
          <ShieldRoundedIcon color="primary" sx={{ fontSize: 36 }} />
          <Typography variant="h5" fontWeight={800} color="white" textAlign="center">
            Sign in to Northstar
          </Typography>
          <Typography variant="body2" color="text.secondary" textAlign="center">
            Welcome back. Enter your credentials to continue.
          </Typography>
        </Stack>

        <form onSubmit={handleSubmit} style={{ display: "block", marginTop: 20 }}>
          <Stack spacing={{ xs: 2.25, sm: 2.75 }}>
            {error && <Alert severity="error">{error}</Alert>}

            <TextField
              label="Email"
              type="email"
              name="email"
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              fullWidth
              InputLabelProps={{ shrink: true }}
            />

            <TextField
              label="Password"
              type="password"
              name="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              fullWidth
              InputLabelProps={{ shrink: true }}
            />

            <Button type="submit" variant="contained" size="large" disabled={loading} fullWidth>
              {loading ? "Signing in..." : "Sign In"}
            </Button>

            <Typography variant="body2" color="text.secondary" textAlign="center">
              Don't have an account?{" "}
              <Box component="a" href="/sign-up" sx={{ color: "primary.main", fontWeight: 600 }}>
                Sign up
              </Box>
            </Typography>
          </Stack>
        </form>
      </Paper>
    </Box>
  );
}

export default SignInPage;