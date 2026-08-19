import { useEffect, useMemo, useRef, useState } from "react";

import CameraAltOutlinedIcon from "@mui/icons-material/CameraAltOutlined";
import CheckCircleRoundedIcon from "@mui/icons-material/CheckCircleRounded";
import CloseRoundedIcon from "@mui/icons-material/CloseRounded";
import FileUploadOutlinedIcon from "@mui/icons-material/FileUploadOutlined";
import ReplayRoundedIcon from "@mui/icons-material/ReplayRounded";
import WarningAmberRoundedIcon from "@mui/icons-material/WarningAmberRounded";
import { Box, Button, Chip, Divider, Stack, Typography } from "@mui/material";

import { BarcodeFormat } from "@zxing/library";
import { BrowserCodeReader, BrowserMultiFormatReader, type IScannerControls } from "@zxing/browser";

import GlassSurface from "../../components/ui/GlassSurface";

type Severity = "low" | "medium" | "high";

type Finding = {
  title: string;
  detail: string;
  severity: Severity;
};

type ScanResult = {
  payload: string;
  format: string;
  source: "camera" | "upload";
  score: number;
  verdict: string;
  findings: Finding[];
};

function formatSeverity(severity: Severity) {
  if (severity === "high") {
    return "High";
  }

  if (severity === "medium") {
    return "Medium";
  }

  return "Low";
}

function severityColor(severity: Severity | string | null | undefined) {
  if (severity === "high") {
    return "#fb7185";
  }

  if (severity === "medium" || severity === "critical") {
    return "#fbbf24";
  }

  if (severity === "low") {
    return "#34d399";
  }

  if (severity === "info") {
    return "#60a5fa";
  }

  return "#7c8aa5";
}

function severityScore(severity: Severity) {
  if (severity === "high") {
    return 35;
  }

  if (severity === "medium") {
    return 15;
  }

  return 5;
}

function getBarcodeFormatName(format: BarcodeFormat) {
  return BarcodeFormat[format] ?? "Unknown";
}

function isSuspiciousHost(hostname: string) {
  const normalized = hostname.toLowerCase();
  return (
    normalized.includes("xn--") ||
    normalized.includes("login") ||
    normalized.includes("secure") ||
    normalized.includes("verify") ||
    normalized.includes("update") ||
    normalized.includes("support") ||
    normalized.includes("account")
  );
}

function buildFindings(payload: string, format: string) {
  const findings: Finding[] = [];

  try {
    const parsed = new URL(payload);

    if (parsed.protocol !== "https:") {
      findings.push({
        title: "Non-HTTPS destination",
        detail: `The code resolves to ${parsed.protocol} and should be reviewed before opening.`,
        severity: "high",
      });
    } else if (isSuspiciousHost(parsed.hostname) || parsed.hostname.split(".").filter(Boolean).length >= 4) {
      findings.push({
        title: "Potential phishing destination",
        detail: `Host ${parsed.hostname} contains phishing indicators or unusual subdomain depth.`,
        severity: "high",
      });
    }
  } catch {
    if (/javascript:|data:/i.test(payload)) {
      findings.push({
        title: "Unsafe payload",
        detail: "The code contains a non-web payload and should be treated as suspicious.",
        severity: "high",
      });
    }
  }

  if (/\b(password|token|secret|admin|reset)\b/i.test(payload)) {
    findings.push({
      title: "Sensitive keyword detected",
      detail: "The payload contains words often seen in credential phishing or abuse flows.",
      severity: "medium",
    });
  }

  if (format === "QR_CODE" && findings.length === 0) {
    findings.push({
      title: "QR code decoded",
      detail: "No obvious malicious indicators were detected in the decoded payload.",
      severity: "low",
    });
  }

  if (findings.length === 0) {
    findings.push({
      title: "Barcode decoded",
      detail: "No obvious malicious indicators were detected in the decoded payload.",
      severity: "low",
    });
  }

  return findings;
}

function loadImage(source: string) {
  return new Promise<HTMLImageElement>((resolve, reject) => {
    const image = new Image();
    image.onload = () => resolve(image);
    image.onerror = () => reject(new Error("Unable to load image."));
    image.src = source;
  });
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = window.setTimeout(() => {
      reject(new Error("Barcode scan timed out. The scanner did not respond within the expected time."));
    }, ms);

    promise.then(
      (value) => {
        window.clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        window.clearTimeout(timer);
        reject(error);
      }
    );
  });
}

function validateImageFile(file: File | null | undefined): string | null {
  if (!file) {
    return "Please upload a valid image file.";
  }

  if (!file.type.startsWith("image/")) {
    return "Please upload a valid image file.";
  }

  if (file.size <= 0) {
    return "The selected file appears to be empty.";
  }

  return null;
}

function scoreForFindings(findings: Finding[]) {
  return Math.min(findings.reduce((sum, finding) => sum + severityScore(finding.severity), 0), 100);
}

function getVerdict(score: number) {
  if (score >= 50) {
    return "High risk";
  }

  if (score >= 25) {
    return "Review required";
  }

  return "No critical signals";
}

function BarcodePage() {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const scannerRef = useRef<BrowserMultiFormatReader | null>(null);
  const controlsRef = useRef<IScannerControls | null>(null);
  const mountedRef = useRef(true);
  const previewUrlRef = useRef<string>("");

  const [mode, setMode] = useState<"idle" | "camera" | "upload">("idle");
  const [isScanning, setIsScanning] = useState(false);
  const [scanError, setScanError] = useState("");
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [selectedFileName, setSelectedFileName] = useState("");
  const [previewUrl, setPreviewUrl] = useState("");

  useEffect(() => {
    return () => {
      mountedRef.current = false;
      controlsRef.current?.stop();
      controlsRef.current = null;
      scannerRef.current = null;
      if (previewUrlRef.current) {
        URL.revokeObjectURL(previewUrlRef.current);
      }
    };
  }, []);

  const stopCameraScan = () => {
    controlsRef.current?.stop();
    controlsRef.current = null;
    scannerRef.current = null;
    if (mountedRef.current) {
      setIsScanning(false);
    }
  };

  const startCameraScan = async () => {
    setMode("camera");
    setScanError("");
    setScanResult(null);

    if (!navigator.mediaDevices?.getUserMedia) {
      setScanError("Camera access is not available in this browser.");
      return;
    }

    try {
      stopCameraScan();
      setIsScanning(true);

      const reader = new BrowserMultiFormatReader();
      scannerRef.current = reader;
      const videoDevices = await BrowserCodeReader.listVideoInputDevices();
      const preferredDeviceId =
        videoDevices.find((device) => /back|rear|environment/i.test(device.label))?.deviceId ?? videoDevices[0]?.deviceId;

      if (!preferredDeviceId) {
        throw new Error("No video input device found.");
      }

      const controls = await reader.decodeFromVideoDevice(preferredDeviceId, videoRef.current ?? undefined, (result, error, scannerControls) => {
        if (error) {
          return;
        }

        if (!result || !mountedRef.current) {
          return;
        }

        const payload = result.getText();
        const format = getBarcodeFormatName(result.getBarcodeFormat());
        const findings = buildFindings(payload, format);
        const score = scoreForFindings(findings);

        scannerControls.stop();
        controlsRef.current = null;
        setScanResult({
          payload,
          format,
          source: "camera",
          score,
          verdict: getVerdict(score),
          findings,
        });
        setIsScanning(false);
      });

      controlsRef.current = controls;
    } catch (error) {
      setScanError(error instanceof Error ? error.message : "Unable to start camera scan.");
      setIsScanning(false);
      stopCameraScan();
    }
  };

  const scanFile = async (file: File | null | undefined) => {
    const validationError = validateImageFile(file);
    if (validationError) {
      setScanError(validationError);
      return;
    }

    if (!file) {
      setScanError("Please upload a valid image file.");
      return;
    }

    setMode("upload");
    setScanError("");
    setScanResult(null);
    setSelectedFileName(file.name);
    setIsScanning(true);
    stopCameraScan();

    if (previewUrlRef.current) {
      URL.revokeObjectURL(previewUrlRef.current);
    }

    const objectUrl = URL.createObjectURL(file);
    previewUrlRef.current = objectUrl;
    setPreviewUrl(objectUrl);

    try {
      const image = await loadImage(objectUrl);
      const reader = new BrowserMultiFormatReader();
      scannerRef.current = reader;
      const result = await withTimeout(reader.decodeFromImageElement(image), 45000);
      const payload = result.getText();
      const format = getBarcodeFormatName(result.getBarcodeFormat());
      const findings = buildFindings(payload, format);
      const score = scoreForFindings(findings);

      if (!mountedRef.current) {
        return;
      }

      setScanResult({
        payload,
        format,
        source: "upload",
        score,
        verdict: getVerdict(score),
        findings,
      });
    } catch (error) {
      if (mountedRef.current) {
        setScanError(error instanceof Error ? error.message : "No barcode or QR code was detected.");
      }
    } finally {
      if (mountedRef.current) {
        setIsScanning(false);
      }
    }
  };

  const handleUploadClick = () => {
    fileInputRef.current?.click();
  };

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];

    if (!file) {
      return;
    }

    void scanFile(file);
  };

  const riskColor = useMemo(() => {
    if (!scanResult) {
      return "#7c8aa5";
    }

    if (scanResult.score >= 50) {
      return "#fb7185";
    }

    if (scanResult.score >= 25) {
      return "#fbbf24";
    }

    return "#34d399";
  }, [scanResult]);

  return (
    <Box sx={{ minHeight: "calc(100vh - 180px)", pb: { xs: 3, md: 5 } }}>
      <Box sx={{ width: "100%", maxWidth: 900, mx: "auto", pt: { xs: 1, md: 2 } }}>
        <Typography variant="h4" sx={{ fontWeight: 800, fontSize: { xs: "1.75rem", md: "2rem" } }}>
          Barcode Threat Scanner
        </Typography>

        <Typography sx={{ mt: 2, color: "text.secondary", maxWidth: 760, lineHeight: 1.7, fontSize: { xs: "0.97rem", md: "1.02rem" } }}>
          Scan barcodes and QR codes for malicious URLs and embedded threats.
        </Typography>
      </Box>

      <GlassSurface
        sx={{
          width: "100%",
          maxWidth: 900,
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
        <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "1fr 1fr" }, gap: 1.5 }}>
          <Box
            onClick={startCameraScan}
            sx={{
              minHeight: 98,
              borderRadius: 4,
              bgcolor: "rgba(255,255,255,0.04)",
              border: "1px solid rgba(255,255,255,0.06)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              cursor: "pointer",
              transition: "160ms ease",
              "&:hover": {
                bgcolor: "rgba(255,255,255,0.06)",
                borderColor: "rgba(255,255,255,0.12)",
              },
            }}
          >
            <Stack spacing={1.2} sx={{ alignItems: "center" }}>
              <CameraAltOutlinedIcon sx={{ fontSize: 28, color: "#e5e7eb" }} />
              <Typography sx={{ fontWeight: 700 }}>Camera Scan</Typography>
            </Stack>
          </Box>

          <Box
            onClick={handleUploadClick}
            sx={{
              minHeight: 98,
              borderRadius: 4,
              bgcolor: "rgba(255,255,255,0.04)",
              border: "1px solid rgba(255,255,255,0.06)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              cursor: "pointer",
              transition: "160ms ease",
              "&:hover": {
                bgcolor: "rgba(255,255,255,0.06)",
                borderColor: "rgba(255,255,255,0.12)",
              },
            }}
          >
            <Stack spacing={1.2} sx={{ alignItems: "center" }}>
              <FileUploadOutlinedIcon sx={{ fontSize: 28, color: "#e5e7eb" }} />
              <Typography sx={{ fontWeight: 700 }}>Upload Image</Typography>
            </Stack>
          </Box>
        </Box>

        <input ref={fileInputRef} type="file" accept="image/*" hidden onChange={handleFileChange} />

        <Divider sx={{ my: 3, borderColor: "rgba(255,255,255,0.08)" }} />

        {mode === "camera" && (
          <Box sx={{ display: "grid", gap: 2.2 }}>
            <Box
              sx={{
                borderRadius: 4,
                bgcolor: "rgba(255,255,255,0.03)",
                border: "1px solid rgba(255,255,255,0.06)",
                overflow: "hidden",
                minHeight: 240,
                position: "relative",
              }}
            >
              <video
                ref={videoRef}
                style={{ width: "100%", height: "100%", minHeight: 240, objectFit: "cover", display: "block" }}
                muted
                playsInline
              />

              {!isScanning && !scanResult && (
                <Box
                  sx={{
                    position: "absolute",
                    inset: 0,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    color: "text.secondary",
                    bgcolor: "rgba(8, 14, 28, 0.2)",
                    pointerEvents: "none",
                  }}
                >
                  <Typography>Camera preview will appear here.</Typography>
                </Box>
              )}
            </Box>

            <Button
              onClick={stopCameraScan}
              fullWidth
              startIcon={<CloseRoundedIcon />}
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
              Stop Camera Scan
            </Button>
          </Box>
        )}

        {mode === "upload" && previewUrl && (
          <Box sx={{ display: "grid", gap: 2.2 }}>
            <Box sx={{ display: "grid", gap: 2, gridTemplateColumns: { xs: "1fr", md: "220px 1fr" }, alignItems: "start" }}>
              <Box
                component="img"
                src={previewUrl}
                alt="Uploaded barcode preview"
                sx={{ width: "100%", borderRadius: 3, border: "1px solid rgba(255,255,255,0.08)" }}
              />

              <Box sx={{ display: "grid", gap: 1.2 }}>
                <Box sx={{ p: 1.5, borderRadius: 2, bgcolor: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.05)" }}>
                  <Typography variant="caption" color="text.secondary">
                    File
                  </Typography>
                  <Typography variant="body2">{selectedFileName || "Uploaded image"}</Typography>
                </Box>
                <Box sx={{ p: 1.5, borderRadius: 2, bgcolor: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.05)" }}>
                  <Typography variant="caption" color="text.secondary">
                    Status
                  </Typography>
                  <Typography variant="body2">{isScanning ? "Scanning image..." : "Ready"}</Typography>
                </Box>
              </Box>
            </Box>
          </Box>
        )}

        {scanError && (
          <Box sx={{ mt: 3, p: 1.5, borderRadius: 2, bgcolor: "rgba(239, 68, 68, 0.08)", border: "1px solid rgba(239, 68, 68, 0.18)" }}>
            <Typography variant="body2" sx={{ color: "#fca5a5" }}>
              {scanError}
            </Typography>
          </Box>
        )}

        {scanResult && (
          <Box sx={{ mt: 3, display: "grid", gap: 2.2 }}>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1.2, alignItems: "center", justifyContent: "space-between" }}>
              <Box>
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                  Scan result
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mt: 0.4 }}>
                  {scanResult.verdict} • Score {scanResult.score}/100
                </Typography>
              </Box>

              <Chip
                label={scanResult.verdict}
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
                  Format
                </Typography>
                <Typography variant="body2">{scanResult.format}</Typography>
              </Box>
              <Box sx={{ p: 1.5, borderRadius: 2, bgcolor: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.05)" }}>
                <Typography variant="caption" color="text.secondary">
                  Source
                </Typography>
                <Typography variant="body2">{scanResult.source === "camera" ? "Camera Scan" : "Upload Image"}</Typography>
              </Box>
            </Box>

            <Box>
              <Typography variant="caption" sx={{ display: "block", mb: 1, letterSpacing: 1, color: "#6f87a8" }}>
                DECODING
              </Typography>
              <Box
                component="pre"
                sx={{
                  m: 0,
                  p: 2,
                  borderRadius: 3,
                  overflow: "auto",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                  bgcolor: "rgba(255,255,255,0.03)",
                  border: "1px solid rgba(255,255,255,0.05)",
                  color: "text.primary",
                  fontFamily: "ui-monospace, SFMono-Regular, Consolas, monospace",
                  fontSize: "0.9rem",
                  lineHeight: 1.7,
                  minHeight: 120,
                }}
              >
                {scanResult.payload}
              </Box>
            </Box>

            <Box>
              <Typography variant="caption" sx={{ display: "block", mb: 1, letterSpacing: 1, color: "#6f87a8" }}>
                FINDINGS
              </Typography>
              <Stack spacing={1.2}>
                {scanResult.findings.map((finding) => (
                  <Box
                    key={`${finding.title}-${finding.detail}`}
                    sx={{
                      p: 1.5,
                      borderRadius: 2,
                      bgcolor: "rgba(255,255,255,0.03)",
                      border: "1px solid rgba(255,255,255,0.05)",
                    }}
                  >
                    <Stack direction="row" spacing={1} sx={{ alignItems: "center", justifyContent: "space-between", flexWrap: "wrap" }}>
                      <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
                        {finding.severity === "high" ? (
                          <WarningAmberRoundedIcon sx={{ color: severityColor(finding.severity) }} fontSize="small" />
                        ) : (
                          <CheckCircleRoundedIcon sx={{ color: severityColor(finding.severity) }} fontSize="small" />
                        )}
                        <Typography variant="body2" sx={{ fontWeight: 700 }}>
                          {finding.title}
                        </Typography>
                      </Stack>

                      <Chip
                        size="small"
                        label={formatSeverity(finding.severity)}
                        sx={{
                          bgcolor: `${severityColor(finding.severity)}1a`,
                          color: severityColor(finding.severity),
                          border: `1px solid ${severityColor(finding.severity)}33`,
                          fontWeight: 700,
                        }}
                      />
                    </Stack>
                    <Typography variant="body2" color="text.secondary" sx={{ mt: 0.8, lineHeight: 1.6 }}>
                      {finding.detail}
                    </Typography>
                  </Box>
                ))}
              </Stack>
            </Box>
          </Box>
        )}

        <Stack direction="row" spacing={1.2} sx={{ justifyContent: "center", mt: 3.5, flexWrap: "wrap" }}>
          {[
            "Camera scan",
            "Upload image",
            "QR decoding",
            "Threat review",
          ].map((item) => (
            <Chip
              key={item}
              label={item}
              variant="outlined"
              sx={{ borderColor: "rgba(255,255,255,0.08)", color: "text.secondary" }}
            />
          ))}
        </Stack>

        <Button
          onClick={() => {
            setMode("idle");
            setScanError("");
            setScanResult(null);
            setSelectedFileName("");
            setPreviewUrl("");
            if (previewUrlRef.current) {
              URL.revokeObjectURL(previewUrlRef.current);
              previewUrlRef.current = "";
            }
            stopCameraScan();
          }}
          fullWidth
          startIcon={<CloseRoundedIcon />}
          sx={{
            mt: 3,
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
          Reset Scanner
        </Button>
      </GlassSurface>
    </Box>
  );
}

export default BarcodePage;
