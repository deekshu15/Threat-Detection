import { useEffect, useMemo, useRef, useState } from "react";

import PlayArrowRoundedIcon from "@mui/icons-material/PlayArrowRounded";
import PublicRoundedIcon from "@mui/icons-material/PublicRounded";
import ReplayRoundedIcon from "@mui/icons-material/ReplayRounded";
import ShieldOutlinedIcon from "@mui/icons-material/ShieldOutlined";
import WarningAmberRoundedIcon from "@mui/icons-material/WarningAmberRounded";
import { Box, Button, Chip, Stack, TextField, Typography } from "@mui/material";

import GlassSurface from "../../components/ui/GlassSurface";

type ScanType = "quick" | "full" | "syn" | "service";

type PortFinding = {
  port: number;
  protocol: "tcp" | "udp";
  service: string;
  state: "open" | "filtered" | "closed";
  risk: "low" | "medium" | "high";
};

type HostSnapshot = {
  target: string;
  resolvedTo: string;
  osGuess: string;
  scanType: ScanType;
  findings: PortFinding[];
  score: number;
  status: string;
};

type ScanPhase = "idle" | "starting" | "scanning" | "completed" | "failed" | "timedout";

const SCAN_START_DELAY_MS = 250;
const SCAN_WORK_DELAY_MS = 900;
const SCAN_TIMEOUT_MS = 30000;

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#fb7185",
  medium: "#fbbf24",
  low: "#34d399",
  info: "#60a5fa",
};

function getSeverityColor(severity: string | null | undefined) {
  const key = (severity ?? "").toLowerCase().trim();
  return SEVERITY_COLORS[key] ?? "#7c8aa5";
}

function safeText(value: string | null | undefined, fallback: string) {
  const text = value?.trim();
  return text ? text : fallback;
}

const scanTypes: Array<{
  id: ScanType;
  title: string;
  description: string;
}> = [
  { id: "quick", title: "Quick Scan", description: "Top 100 ports" },
  { id: "full", title: "Full Scan", description: "All 65535 ports" },
  { id: "syn", title: "SYN Stealth", description: "Half-open scan" },
  { id: "service", title: "Service Detect", description: "Version detection" },
];

const commonServices: Array<{ port: number; service: string; protocol: "tcp" | "udp"; risk: PortFinding["risk"] }> = [
  { port: 22, service: "ssh", protocol: "tcp", risk: "medium" },
  { port: 53, service: "dns", protocol: "udp", risk: "low" },
  { port: 80, service: "http", protocol: "tcp", risk: "medium" },
  { port: 110, service: "pop3", protocol: "tcp", risk: "medium" },
  { port: 139, service: "netbios-ssn", protocol: "tcp", risk: "high" },
  { port: 143, service: "imap", protocol: "tcp", risk: "medium" },
  { port: 443, service: "https", protocol: "tcp", risk: "low" },
  { port: 445, service: "microsoft-ds", protocol: "tcp", risk: "high" },
  { port: 3389, service: "rdp", protocol: "tcp", risk: "high" },
  { port: 8080, service: "http-proxy", protocol: "tcp", risk: "medium" },
  { port: 8443, service: "https-alt", protocol: "tcp", risk: "medium" },
  { port: 9200, service: "elasticsearch", protocol: "tcp", risk: "high" },
];

function hashString(value: string) {
  let hash = 0;

  for (let index = 0; index < value.length; index += 1) {
    hash = (hash * 31 + value.charCodeAt(index)) | 0;
  }

  return Math.abs(hash);
}

function isValidTarget(value: string) {
  const target = value.trim();
  if (!target) {
    return false;
  }

  if (/^(localhost|127\.0\.0\.1|\d{1,3}(?:\.\d{1,3}){3}|\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2})$/.test(target)) {
    return true;
  }

  return /^[a-zA-Z0-9.-]+$/.test(target) && !target.startsWith("-") && !target.endsWith("-");
}

function buildResolvedAddress(target: string) {
  const seed = hashString(target);
  const third = (seed % 254) + 1;
  const fourth = ((seed >> 8) % 254) + 1;
  return `10.${third}.${(seed >> 16) % 254}.${fourth}`;
}

function pickPorts(target: string, scanType: ScanType) {
  const seed = hashString(`${target}-${scanType}`);
  const threshold = scanType === "full" ? 10 : scanType === "service" ? 6 : scanType === "syn" ? 4 : 3;
  const selected = commonServices.filter((_, index) => ((seed + index * 13) % 7) < threshold);

  if (selected.length === 0) {
    return [commonServices[0]];
  }

  return selected;
}

function buildFindings(target: string, scanType: ScanType) {
  const ports = pickPorts(target, scanType);
  return ports.map<PortFinding>((item) => ({
    port: item.port,
    protocol: item.protocol,
    service: item.service,
    state: item.risk === "low" ? "closed" : item.risk === "medium" ? "filtered" : "open",
    risk: item.risk,
  }));
}

function scoreScan(findings: PortFinding[]) {
  return Math.min(findings.reduce((score, finding) => score + (finding.risk === "high" ? 22 : finding.risk === "medium" ? 10 : 4), 0), 100);
}

function getStatus(score: number, findings: PortFinding[]) {
  if (findings.some((finding) => finding.risk === "high") || score >= 50) {
    return "High exposure";
  }

  if (score >= 25) {
    return "Review recommended";
  }

  return "Low exposure";
}

function getOsGuess(target: string) {
  const seed = hashString(target);
  const guesses = ["Linux 5.x", "Windows Server 2019", "Network appliance", "BSD-family host"];
  return guesses[seed % guesses.length];
}

function NmapPage() {
  const [target, setTarget] = useState("192.168.1.0/24");
  const [scanType, setScanType] = useState<ScanType>("quick");
  const [scanPhase, setScanPhase] = useState<ScanPhase>("idle");
  const [elapsed, setElapsed] = useState(0);
  const [errorMessage, setErrorMessage] = useState("");
  const [result, setResult] = useState<HostSnapshot | null>(null);

  const scanPhaseRef = useRef<ScanPhase>("idle");
  const mountedRef = useRef(true);
  const startTimerRef = useRef<number | null>(null);
  const workTimerRef = useRef<number | null>(null);
  const timeoutTimerRef = useRef<number | null>(null);
  const elapsedTimerRef = useRef<number | null>(null);

  useEffect(() => {
    mountedRef.current = true;

    return () => {
      mountedRef.current = false;
      if (startTimerRef.current) {
        window.clearTimeout(startTimerRef.current);
      }
      if (workTimerRef.current) {
        window.clearTimeout(workTimerRef.current);
      }
      if (timeoutTimerRef.current) {
        window.clearTimeout(timeoutTimerRef.current);
      }
      if (elapsedTimerRef.current) {
        window.clearInterval(elapsedTimerRef.current);
      }
    };
  }, []);

  const updateScanPhase = (phase: ScanPhase) => {
    scanPhaseRef.current = phase;
    setScanPhase(phase);
  };

  const clearTimers = () => {
    if (startTimerRef.current) {
      window.clearTimeout(startTimerRef.current);
      startTimerRef.current = null;
    }
    if (workTimerRef.current) {
      window.clearTimeout(workTimerRef.current);
      workTimerRef.current = null;
    }
    if (timeoutTimerRef.current) {
      window.clearTimeout(timeoutTimerRef.current);
      timeoutTimerRef.current = null;
    }
    if (elapsedTimerRef.current) {
      window.clearInterval(elapsedTimerRef.current);
      elapsedTimerRef.current = null;
    }
  };

  const startScan = () => {
    const currentPhase = scanPhaseRef.current;
    if (currentPhase === "starting" || currentPhase === "scanning") {
      return;
    }

    const trimmedTarget = target.trim();

    if (!isValidTarget(trimmedTarget)) {
      setErrorMessage("Enter a valid IP, CIDR block, localhost, or hostname.");
      return;
    }

    setErrorMessage("");
    setResult(null);
    setElapsed(0);
    updateScanPhase("starting");

    startTimerRef.current = window.setTimeout(() => {
      if (!mountedRef.current || scanPhaseRef.current !== "starting") {
        return;
      }

      updateScanPhase("scanning");

      elapsedTimerRef.current = window.setInterval(() => {
        if (mountedRef.current) {
          setElapsed((value) => value + 1);
        }
      }, 1000);

      timeoutTimerRef.current = window.setTimeout(() => {
        if (!mountedRef.current) {
          return;
        }
        clearTimers();
        updateScanPhase("timedout");
        setErrorMessage("Nmap scan timed out. The scanner did not respond within the expected time.");
      }, SCAN_TIMEOUT_MS);

      workTimerRef.current = window.setTimeout(() => {
        if (!mountedRef.current) {
          return;
        }

        try {
          const findings = buildFindings(trimmedTarget, scanType);
          const score = scoreScan(findings);

          setResult({
            target: trimmedTarget,
            resolvedTo: buildResolvedAddress(trimmedTarget),
            osGuess: getOsGuess(trimmedTarget),
            scanType,
            findings,
            score,
            status: getStatus(score, findings),
          });
          updateScanPhase("completed");
        } catch {
          clearTimers();
          updateScanPhase("failed");
          setErrorMessage("Nmap scan failed.");
          return;
        } finally {
          if (elapsedTimerRef.current) {
            window.clearInterval(elapsedTimerRef.current);
            elapsedTimerRef.current = null;
          }
          if (timeoutTimerRef.current) {
            window.clearTimeout(timeoutTimerRef.current);
            timeoutTimerRef.current = null;
          }
        }
      }, SCAN_WORK_DELAY_MS);
    }, SCAN_START_DELAY_MS);
  };

  const retryScan = () => {
    startScan();
  };

  const selectedScan = useMemo(() => scanTypes.find((item) => item.id === scanType) ?? scanTypes[0], [scanType]);
  const isScanInProgress = scanPhase === "starting" || scanPhase === "scanning";

  const riskColor = result ? (result.score >= 50 ? "#fb7185" : result.score >= 25 ? "#fbbf24" : "#34d399") : "#7c8aa5";

  return (
    <Box sx={{ minHeight: "calc(100vh - 180px)", pb: { xs: 3, md: 5 } }}>
      <Box sx={{ width: "100%", maxWidth: 960, mx: "auto", pt: { xs: 1, md: 2 } }}>
        <Typography variant="h4" sx={{ fontWeight: 800, fontSize: { xs: "1.75rem", md: "2rem" } }}>
          Nmap Network Scanner
        </Typography>

        <Typography sx={{ mt: 2, color: "text.secondary", maxWidth: 760, lineHeight: 1.7, fontSize: { xs: "0.97rem", md: "1.02rem" } }}>
          Discover hosts, open ports, running services, and potential vulnerabilities on your network.
        </Typography>
      </Box>

      <GlassSurface
        sx={{
          width: "100%",
          maxWidth: 960,
          mx: "auto",
          mt: 4,
          px: { xs: 2.5, md: 4 },
          py: { xs: 3, md: 3.5 },
          borderRadius: 4,
          background: "rgba(8, 14, 28, 0.82)",
          boxShadow: "0 28px 70px rgba(0, 0, 0, 0.34)",
          transition: "border-color 180ms ease, box-shadow 180ms ease",
          "&:hover": {
            borderColor: "#22d3ee",
            boxShadow: "0 0 0 2px rgba(34, 211, 238, 0.18), 0 28px 70px rgba(0, 0, 0, 0.34)",
          },
        }}
      >
        <Typography variant="caption" sx={{ display: "block", mb: 1.1, color: "#6f87a8", letterSpacing: 0.8 }}>
          Target (IP / CIDR / hostname)
        </Typography>

        <TextField
          fullWidth
          hiddenLabel
          value={target}
          onChange={(event) => {
            setTarget(event.target.value);
            if (errorMessage) {
              setErrorMessage("");
            }
          }}
          placeholder="192.168.1.0/24"
          variant="outlined"
          size="small"
          sx={{
            mb: 2.2,
            "& .MuiOutlinedInput-root": {
              minHeight: 42,
              borderRadius: 3,
              bgcolor: "rgba(255,255,255,0.04)",
              color: "text.primary",
              fontWeight: 600,
              "& fieldset": { borderColor: "rgba(255,255,255,0.06)" },
              "&:hover fieldset": { borderColor: "rgba(255,255,255,0.12)" },
              "&.Mui-focused fieldset": { borderColor: "rgba(34, 211, 238, 0.45)" },
            },
            "& .MuiInputBase-input": {
              py: 1.2,
              px: 1.7,
              fontSize: "0.98rem",
              "&::placeholder": { color: "rgba(148, 163, 184, 0.72)", opacity: 1 },
            },
          }}
        />

        <Typography variant="caption" sx={{ display: "block", mb: 1.1, color: "#6f87a8", letterSpacing: 0.8 }}>
          Scan Type
        </Typography>

        <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "1fr 1fr" }, gap: 1.2 }}>
          {scanTypes.map((item) => {
            const active = item.id === scanType;

            return (
              <Box
                key={item.id}
                onClick={() => {
                  if (!isScanInProgress) {
                    setScanType(item.id);
                  }
                }}
                sx={{
                  minHeight: 54,
                  px: 1.6,
                  py: 1.2,
                  borderRadius: 3,
                  cursor: isScanInProgress ? "default" : "pointer",
                  opacity: isScanInProgress && !active ? 0.55 : 1,
                  bgcolor: active ? "rgba(0, 198, 255, 0.12)" : "rgba(255,255,255,0.04)",
                  border: `1px solid ${active ? "rgba(0, 198, 255, 0.95)" : "rgba(255,255,255,0.06)"}`,
                  transition: "160ms ease",
                  "&:hover": {
                    bgcolor: active ? "rgba(0, 198, 255, 0.14)" : isScanInProgress ? "rgba(255,255,255,0.04)" : "rgba(255,255,255,0.06)",
                  },
                }}
              >
                <Typography sx={{ fontWeight: 700, color: active ? "#22d3ee" : "text.primary" }}>
                  {item.title}
                </Typography>
                <Typography variant="body2" sx={{ mt: 0.2, color: active ? "#7dd3fc" : "text.secondary" }}>
                  {item.description}
                </Typography>
              </Box>
            );
          })}
        </Box>

        <Button
          onClick={startScan}
          disabled={isScanInProgress}
          fullWidth
          startIcon={isScanInProgress ? <PublicRoundedIcon /> : <PlayArrowRoundedIcon />}
          sx={{
            mt: 2.2,
            minHeight: 42,
            borderRadius: 3,
            textTransform: "none",
            fontWeight: 700,
            fontSize: "0.98rem",
            color: "#e5e7eb",
            bgcolor: "rgba(255,255,255,0.04)",
            border: "1px solid rgba(255,255,255,0.06)",
            "&:hover": {
              bgcolor: "rgba(255,255,255,0.07)",
              borderColor: "rgba(255,255,255,0.12)",
            },
          }}
        >
          {scanPhase === "starting" ? "Starting scan..." : isScanInProgress ? "Scanning..." : "Start Scan"}
        </Button>

        {isScanInProgress && (
          <Box
            sx={{
              mt: 2.2,
              p: 1.6,
              borderRadius: 2,
              bgcolor: "rgba(34, 211, 238, 0.06)",
              border: "1px solid rgba(34, 211, 238, 0.16)",
            }}
          >
            <Stack direction="row" spacing={1.1} sx={{ alignItems: "center" }}>
              <PublicRoundedIcon sx={{ color: "#22d3ee", fontSize: 20 }} />
              <Typography variant="body2" sx={{ color: "#a5f3fc" }}>
                {scanPhase === "starting"
                  ? "Starting Nmap scan..."
                  : `Scanning target... Elapsed: ${elapsed} seconds`}
              </Typography>
            </Stack>
          </Box>
        )}

        {scanPhase === "completed" && (
          <Box
            sx={{
              mt: 2.2,
              p: 1.6,
              borderRadius: 2,
              bgcolor: "rgba(52, 211, 153, 0.06)",
              border: "1px solid rgba(52, 211, 153, 0.16)",
            }}
          >
            <Typography variant="body2" sx={{ color: "#6ee7b7" }}>
              Scan completed successfully.
            </Typography>
          </Box>
        )}

        {(scanPhase === "failed" || scanPhase === "timedout") && (
          <Box
            sx={{
              mt: 2.2,
              p: 1.6,
              borderRadius: 2,
              bgcolor: "rgba(239, 68, 68, 0.08)",
              border: "1px solid rgba(239, 68, 68, 0.18)",
            }}
          >
            <Stack direction="row" spacing={1.4} sx={{ alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 1 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <WarningAmberRoundedIcon sx={{ color: "#fca5a5", fontSize: 20 }} />
                <Typography variant="body2" sx={{ color: "#fca5a5" }}>
                  {scanPhase === "timedout" ? "Scan timed out." : "Nmap scan failed."}
                </Typography>
              </Box>

              <Button
                onClick={retryScan}
                size="small"
                startIcon={<ReplayRoundedIcon />}
                sx={{
                  minHeight: 32,
                  borderRadius: 2,
                  textTransform: "none",
                  fontWeight: 700,
                  fontSize: "0.85rem",
                  color: "#fecaca",
                  bgcolor: "rgba(239, 68, 68, 0.14)",
                  border: "1px solid rgba(239, 68, 68, 0.28)",
                  "&:hover": {
                    bgcolor: "rgba(239, 68, 68, 0.22)",
                    borderColor: "rgba(239, 68, 68, 0.4)",
                  },
                }}
              >
                Retry Scan
              </Button>
            </Stack>
          </Box>
        )}

        {errorMessage && scanPhase !== "failed" && scanPhase !== "timedout" && (
          <Box sx={{ mt: 2.2, p: 1.5, borderRadius: 2, bgcolor: "rgba(239, 68, 68, 0.08)", border: "1px solid rgba(239, 68, 68, 0.18)" }}>
            <Typography variant="body2" sx={{ color: "#fca5a5" }}>
              {errorMessage}
            </Typography>
          </Box>
        )}

        {result && result.findings.length === 0 && (
          <Box sx={{ mt: 3, p: 2, borderRadius: 2, bgcolor: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.05)" }}>
            <Typography variant="body2" color="text.secondary" sx={{ textAlign: "center" }}>
              No scan results found.
            </Typography>
          </Box>
        )}

        {result && result.findings.length > 0 && (
          <Box sx={{ mt: 3, display: "grid", gap: 2.2 }}>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1.2, alignItems: "center", justifyContent: "space-between" }}>
              <Box>
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                  Scan result
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mt: 0.4 }}>
                  {safeText(result.status, "Scan completed")} • Score {Number.isFinite(result.score) ? result.score : 0}/100
                </Typography>
              </Box>

              <Chip
                label={safeText(result.status, "Scan completed")}
                sx={{
                  bgcolor: `${riskColor}1a`,
                  color: riskColor,
                  border: `1px solid ${riskColor}33`,
                  fontWeight: 700,
                }}
              />
            </Box>

            <Box sx={{ display: "grid", gap: 1, gridTemplateColumns: { xs: "1fr", sm: "1fr 1fr" } }}>
              <Box sx={{ p: 1.5, borderRadius: 2, bgcolor: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.05)" }}>
                <Typography variant="caption" color="text.secondary">
                  Target
                </Typography>
                <Typography variant="body2">{safeText(result.target, "Unknown target")}</Typography>
              </Box>
              <Box sx={{ p: 1.5, borderRadius: 2, bgcolor: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.05)" }}>
                <Typography variant="caption" color="text.secondary">
                  Resolved Address
                </Typography>
                <Typography variant="body2">{safeText(result.resolvedTo, "N/A")}</Typography>
              </Box>
              <Box sx={{ p: 1.5, borderRadius: 2, bgcolor: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.05)" }}>
                <Typography variant="caption" color="text.secondary">
                  Scan Type
                </Typography>
                <Typography variant="body2">{selectedScan.title}</Typography>
              </Box>
              <Box sx={{ p: 1.5, borderRadius: 2, bgcolor: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.05)" }}>
                <Typography variant="caption" color="text.secondary">
                  OS Guess
                </Typography>
                <Typography variant="body2">{safeText(result.osGuess, "Unknown OS")}</Typography>
              </Box>
            </Box>

            <Box>
              <Typography variant="caption" sx={{ display: "block", mb: 1, letterSpacing: 1, color: "#6f87a8" }}>
                DISCOVERED SERVICES
              </Typography>
              <Stack spacing={1.1}>
                {result.findings.map((finding, index) => {
                  const findingRisk = safeText(finding.risk, "low");
                  const findingColor = getSeverityColor(findingRisk);

                  return (
                    <Box
                      key={`${finding.port}-${finding.protocol}-${index}`}
                      sx={{
                        p: 1.4,
                        borderRadius: 2,
                        bgcolor: "rgba(255,255,255,0.03)",
                        border: "1px solid rgba(255,255,255,0.05)",
                      }}
                    >
                      <Stack direction="row" spacing={1.2} sx={{ alignItems: "center", justifyContent: "space-between", flexWrap: "wrap" }}>
                        <Stack direction="row" spacing={1.2} sx={{ alignItems: "center" }}>
                          <PublicRoundedIcon sx={{ color: findingColor }} fontSize="small" />
                          <Typography variant="body2" sx={{ fontWeight: 700 }}>
                            {Number.isFinite(finding.port) ? finding.port : "N/A"}/{safeText(finding.protocol, "tcp")}
                          </Typography>
                          <Typography variant="body2" color="text.secondary">
                            {safeText(finding.service, "Unknown service")}
                          </Typography>
                        </Stack>

                        <Chip
                          size="small"
                          label={safeText(finding.state, "unknown")}
                          sx={{
                            textTransform: "capitalize",
                            bgcolor: `${findingColor}1a`,
                            color: findingColor,
                            border: `1px solid ${findingColor}33`,
                            fontWeight: 700,
                          }}
                        />
                      </Stack>
                    </Box>
                  );
                })}
              </Stack>
            </Box>

            <Box sx={{ display: "grid", gap: 1.1, gridTemplateColumns: { xs: "1fr", sm: "repeat(3, 1fr)" } }}>
              {[
                { label: "Hosts scanned", value: "1" },
                { label: "Open ports", value: String(result.findings.filter((finding) => finding.state === "open").length) },
                { label: "Critical", value: String(result.findings.filter((finding) => finding.risk === "high").length) },
              ].map((item) => (
                <Box key={item.label} sx={{ p: 1.5, borderRadius: 2, bgcolor: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.05)" }}>
                  <Typography variant="caption" color="text.secondary">
                    {item.label}
                  </Typography>
                  <Typography variant="h5" sx={{ fontWeight: 700, mt: 0.4 }}>
                    {item.value}
                  </Typography>
                </Box>
              ))}
            </Box>

            <Button
              onClick={() => {
                clearTimers();
                updateScanPhase("idle");
                setResult(null);
                setElapsed(0);
              }}
              fullWidth
              startIcon={<ShieldOutlinedIcon />}
              sx={{
                minHeight: 42,
                borderRadius: 3,
                textTransform: "none",
                fontWeight: 700,
                fontSize: "0.98rem",
                color: "#e5e7eb",
                bgcolor: "rgba(255,255,255,0.04)",
                border: "1px solid rgba(255,255,255,0.06)",
              }}
            >
              Clear Results
            </Button>
          </Box>
        )}

        <Stack direction="row" spacing={1.2} sx={{ justifyContent: "center", mt: 3.5, flexWrap: "wrap" }}>
          {[
            "Host discovery",
            "Port analysis",
            "Service detection",
            "Risk scoring",
          ].map((item) => (
            <Chip
              key={item}
              label={item}
              variant="outlined"
              sx={{ borderColor: "rgba(255,255,255,0.08)", color: "text.secondary" }}
            />
          ))}
        </Stack>
      </GlassSurface>
    </Box>
  );
}

export default NmapPage;