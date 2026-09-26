import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Box, Button, Paper, Stack, TextField, Typography, Alert } from "@mui/material";
import ShieldRoundedIcon from "@mui/icons-material/ShieldRounded";

import { authService } from "../auth/authService";

function SignUpPage() {
  const navigate = useNavigate();
  const [step, setStep] = useState<"register" | "confirm">("register");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await authService.register(email, password, name);
      setStep("confirm");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign up failed.");
    } finally {
      setLoading(false);
    }
  };

  const handleConfirm = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await authService.confirmRegistration(email, code);
      await authService.login(email, password);
      navigate("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification failed.");
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
          p: 5,
          width: "100%",
          maxWidth: 420,
          borderRadius: 4,
          border: "1px solid rgba(255,255,255,0.12)",
          bgcolor: "rgba(255,255,255,0.05)",
          backdropFilter: "blur(16px)",
        }}
      >
        <Stack spacing={1} alignItems="center" mb={4}>
          <ShieldRoundedIcon color="primary" sx={{ fontSize: 36 }} />
          <Typography variant="h5" fontWeight={800} color="white">
            {step === "register" ? "Create your account" : "Verify your email"}
          </Typography>
          <Typography variant="body2" color="text.secondary" textAlign="center">
            {step === "register"
              ? "Join Northstar Security to get started."
              : `Enter the 6-digit code sent to ${email}.`}
          </Typography>
        </Stack>

        {step === "register" ? (
          <form onSubmit={handleRegister} style={{ display: "block", marginTop: 20 }}>
            <Stack spacing={2.5}>
              {error && <Alert severity="error">{error}</Alert>}

              <TextField label="Full name" value={name} onChange={(e) => setName(e.target.value)} required fullWidth />
              <TextField label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required fullWidth />
              <TextField label="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required fullWidth helperText="At least 8 characters, with uppercase and lowercase letters and a number." />

              <Button type="submit" variant="contained" size="large" disabled={loading} fullWidth>
                {loading ? "Creating account..." : "Sign Up"}
              </Button>

              <Typography variant="body2" color="text.secondary" textAlign="center">
                Already have an account?{" "}
                <Box component="a" href="/sign-in" sx={{ color: "primary.main", fontWeight: 600 }}>
                  Sign in
                </Box>
              </Typography>
            </Stack>
          </form>
        ) : (
          <form onSubmit={handleConfirm} style={{ display: "block", marginTop: 20 }}>
            <Stack spacing={2.5}>
              {error && <Alert severity="error">{error}</Alert>}

              <TextField label="Verification code" value={code} onChange={(e) => setCode(e.target.value)} required fullWidth />

              <Button type="submit" variant="contained" size="large" disabled={loading} fullWidth>
                {loading ? "Verifying..." : "Verify & Continue"}
              </Button>
            </Stack>
          </form>
        )}
      </Paper>
    </Box>
  );
}

export default SignUpPage;