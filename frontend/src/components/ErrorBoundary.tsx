import { Component, type ErrorInfo, type ReactNode } from "react";

import ReplayRoundedIcon from "@mui/icons-material/ReplayRounded";
import HomeRoundedIcon from "@mui/icons-material/HomeRounded";
import { Box, Button, Stack, Typography } from "@mui/material";

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    // Keep the underlying error visible in the console during development.
    console.error("ErrorBoundary caught an error:", error, errorInfo);
  }

  private handleReload = () => {
    window.location.reload();
  };

  private handleGoHome = () => {
    window.location.href = "/dashboard";
  };

  render() {
    if (this.state.hasError) {
      return (
        <Box
          sx={{
            minHeight: "100vh",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            bgcolor: "#0b0f14",
            color: "#ffffff",
            p: 3,
          }}
        >
          <Stack spacing={2.5} sx={{ alignItems: "center", textAlign: "center", maxWidth: 480 }}>
            <Typography variant="h5" sx={{ fontWeight: 800 }}>
              Something went wrong while loading this page.
            </Typography>

            <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.7 }}>
              The application hit an unexpected error. You can reload the page to try again, or return to the dashboard.
            </Typography>

            {this.state.error?.message && (
              <Box
                sx={{
                  width: "100%",
                  p: 1.5,
                  borderRadius: 2,
                  bgcolor: "rgba(239, 68, 68, 0.08)",
                  border: "1px solid rgba(239, 68, 68, 0.18)",
                  color: "#fca5a5",
                  fontSize: "0.8rem",
                  fontFamily: "ui-monospace, SFMono-Regular, Consolas, monospace",
                  wordBreak: "break-word",
                  textAlign: "left",
                }}
              >
                {this.state.error.message}
              </Box>
            )}

            <Stack direction="row" spacing={1.5} sx={{ flexWrap: "wrap", justifyContent: "center" }}>
              <Button
                onClick={this.handleReload}
                variant="contained"
                startIcon={<ReplayRoundedIcon />}
                sx={{ textTransform: "none", fontWeight: 700 }}
              >
                Reload Page
              </Button>

              <Button
                onClick={this.handleGoHome}
                variant="outlined"
                startIcon={<HomeRoundedIcon />}
                sx={{ textTransform: "none", fontWeight: 700 }}
              >
                Go to Dashboard
              </Button>
            </Stack>
          </Stack>
        </Box>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;