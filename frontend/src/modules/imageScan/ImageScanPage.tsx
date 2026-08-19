import { useEffect, useMemo, useRef, useState } from "react";

import InsertPhotoOutlinedIcon from "@mui/icons-material/InsertPhotoOutlined";
import ReplayRoundedIcon from "@mui/icons-material/ReplayRounded";
import WarningAmberRoundedIcon from "@mui/icons-material/WarningAmberRounded";
import CheckCircleRoundedIcon from "@mui/icons-material/CheckCircleRounded";
import CloseRoundedIcon from "@mui/icons-material/CloseRounded";
import { Box, Button, Chip, Divider, Stack, Typography } from "@mui/material";

import jsQR from "jsqr";
import exifr from "exifr";

import GlassSurface from "../../components/ui/GlassSurface";
import { saveSecurityEvent } from "../shared/eventsService";

type Severity = "low" | "medium" | "high";

type Finding = {
  title: string;
  detail: string;
  severity: Severity;
};

type ScanResult = {
  fileName: string;
  fileType: string;
  fileSize: number;
  width: number;
  height: number;
  score: number;
  verdict: string;
  qrData: string | null;
  exifSummary: string[];
  findings: Finding[];
};

const SCAN_TIMEOUT_MS = 45000;
const MAX_FILE_SIZE_BYTES = 15 * 1024 * 1024;

const ALLOWED_IMAGE_TYPES = ["image/jpeg", "image/png", "image/webp", "image/gif", "image/bmp", "image/avif", "image/tiff"];

function formatBytes(bytes: number) {
  if (bytes < 1024) {
    return `${bytes} B`;
  }

  const kilobytes = bytes / 1024;
  if (kilobytes < 1024) {
    return `${kilobytes.toFixed(1)} KB`;
  }

  return `${(kilobytes / 1024).toFixed(1)} MB`;
}

function severityLabel(severity: Severity) {
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

function scoreImpact(severity: Severity) {
  if (severity === "high") {
    return 35;
  }
  if (severity === "medium") {
    return 15;
  }
  return 5;
}

function isLikelySuspiciousHost(hostname: string) {
  const lowered = hostname.toLowerCase();
  return (
    lowered.includes("xn--") ||
    lowered.includes("login") ||
    lowered.includes("secure") ||
    lowered.includes("verify") ||
    lowered.includes("update") ||
    lowered.includes("support")
  );
}

function getHostDepth(hostname: string) {
  return hostname.split(".").filter(Boolean).length;
}

function toExifSummary(exifData: Record<string, unknown> | null) {
  if (!exifData) {
    return [];
  }

  const entries: string[] = [];
  const software = typeof exifData.Software === "string" ? exifData.Software : "";
  const artist = typeof exifData.Artist === "string" ? exifData.Artist : "";
  const creator = typeof exifData.CreatorTool === "string" ? exifData.CreatorTool : "";
  const gpsLatitude = exifData.latitude ?? exifData.GPSLatitude;
  const gpsLongitude = exifData.longitude ?? exifData.GPSLongitude;
  const comment = typeof exifData.UserComment === "string" ? exifData.UserComment : "";

  if (software) entries.push(`Software: ${software}`);
  if (artist) entries.push(`Artist: ${artist}`);
  if (creator) entries.push(`Creator tool: ${creator}`);
  if (gpsLatitude && gpsLongitude) entries.push("GPS coordinates embedded");
  if (comment) entries.push("User comment present");

  return entries;
}

async function loadImage(source: string) {
  return await new Promise<HTMLImageElement>((resolve, reject) => {
    const image = new Image();
    image.onload = () => resolve(image);
    image.onerror = () => reject(new Error("Unable to load image."));
    image.src = source;
  });
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = window.setTimeout(() => {
      reject(new Error("Image scan timed out. The scanner did not respond within the expected time."));
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

  if (!ALLOWED_IMAGE_TYPES.includes(file.type)) {
    return "Unsupported image format. Please use JPEG, PNG, WebP, GIF, BMP, AVIF, or TIFF.";
  }

  if (file.size <= 0) {
    return "The selected file appears to be empty.";
  }

  if (file.size > MAX_FILE_SIZE_BYTES) {
    return "Image is too large. Maximum allowed size is 15 MB.";
  }

  return null;
}

async function scanImage(file: File): Promise<ScanResult> {
  const objectUrl = URL.createObjectURL(file);
  try {
    const image = await loadImage(objectUrl);
    const canvas = document.createElement("canvas");
    const context = canvas.getContext("2d");

    if (!context) {
      throw new Error("Canvas context is unavailable.");
    }

    if (!image.naturalWidth || !image.naturalHeight) {
      throw new Error("The selected image could not be decoded.");
    }

    canvas.width = image.naturalWidth;
    canvas.height = image.naturalHeight;
    context.drawImage(image, 0, 0);

    const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
    const qr = jsQR(imageData.data, canvas.width, canvas.height, {
      inversionAttempts: "dontInvert",
    });

    const exifData = (await exifr.parse(file).catch(() => null)) as Record<string, unknown> | null;
    const exifSummary = toExifSummary(exifData);
    const findings: Finding[] = [];

    if (qr?.data) {
      let qrFinding: Finding = {
        title: "QR code detected",
        detail: `Embedded payload found: ${qr.data}`,
        severity: "medium",
      };

      try {
        const parsed = new URL(qr.data);
        if (parsed.protocol !== "https:") {
          qrFinding = {
            title: "QR code points to non-HTTPS URL",
            detail: `The QR payload uses ${parsed.protocol} and should be reviewed before opening.`,
            severity: "high",
          };
        } else if (isLikelySuspiciousHost(parsed.hostname) || getHostDepth(parsed.hostname) >= 4) {
          qrFinding = {
            title: "QR code points to a suspicious destination",
            detail: `Host ${parsed.hostname} includes phishing indicators or an unusual subdomain depth.`,
            severity: "high",
          };
        }
      } catch {
        if (/javascript:|data:/i.test(qr.data)) {
          qrFinding = {
            title: "Dangerous QR payload",
            detail: "The QR content contains a non-web payload and should be treated as unsafe.",
            severity: "high",
          };
        }
      }

      findings.push(qrFinding);
    }

    if (exifSummary.length > 0) {
      findings.push({
        title: "Metadata present",
        detail: exifSummary.join(" • "),
        severity: exifSummary.some((item) => item.includes("GPS")) ? "high" : "medium",
      });
    }

    if (file.name.split(".").length > 2) {
      findings.push({
        title: "Multiple file extensions",
        detail: "The filename includes more than one extension, which is often used to disguise content.",
        severity: "medium",
      });
    }

    if (!file.type.startsWith("image/")) {
      findings.push({
        title: "Unexpected MIME type",
        detail: `Browser reported ${file.type || "unknown"} for this file.`,
        severity: "medium",
      });
    }

    if (canvas.width >= 4000 || canvas.height >= 4000) {
      findings.push({
        title: "Large image dimensions",
        detail: "Oversized images can hide payloads or stress decoding logic.",
        severity: "low",
      });
    }

    const score = findings.reduce((sum, finding) => sum + scoreImpact(finding.severity), 0);
    const verdict =
      score >= 50
        ? "High risk"
        : score >= 25
          ? "Review required"
          : "No high-risk signals found";

    if (findings.length === 0) {
      findings.push({
        title: "No obvious malicious signals",
        detail: "No QR payload, suspicious metadata, or filename anomalies were detected.",
        severity: "low",
      });
    }

    return {
      fileName: file.name,
      fileType: file.type || "unknown",
      fileSize: file.size,
      width: canvas.width,
      height: canvas.height,
      score: Math.min(score, 100),
      verdict,
      qrData: qr?.data ?? null,
      exifSummary,
      findings,
    };
  } finally {
    URL.revokeObjectURL(objectUrl);
  }
}

function ImageScanPage() {
  const inputRef = useRef<HTMLInputElement | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);

  const scanningRef = useRef(false);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;

    return () => {
      mountedRef.current = false;
      if (previewUrl) {
        URL.revokeObjectURL(previewUrl);
      }
    };
  }, [previewUrl]);

  const handleFile = async (file: File | null | undefined) => {
    if (scanningRef.current) {
      return;
    }

    const validationError = validateImageFile(file);
    if (validationError) {
      setErrorMessage(validationError);
      setSelectedFile(null);
      setResult(null);
      return;
    }

    if (!file) {
      setErrorMessage("Please upload a valid image file.");
      return;
    }

    setErrorMessage("");
    setSelectedFile(file);
    setResult(null);
    setIsScanning(true);
    scanningRef.current = true;

    if (previewUrl) {
      URL.revokeObjectURL(previewUrl);
    }

    const nextPreviewUrl = URL.createObjectURL(file);
    setPreviewUrl(nextPreviewUrl);

    try {
      const scan = await withTimeout(scanImage(file), SCAN_TIMEOUT_MS);
      if (mountedRef.current) {
        setResult(scan);
        const highFindings = scan.findings.filter((f) => f.severity === "high");
        if (highFindings.length > 0) {
          void saveSecurityEvent({
            event_id: `img-${Date.now()}`,
            timestamp: new Date().toISOString(),
            source: "Image Scanner",
            tool: "Image Scanner",
            attack_type: highFindings[0].title,
            severity: "High",
            risk_score: scan.score,
            status: scan.verdict,
            description: highFindings.map((f) => f.detail).join(" | "),
            recommendation: "Review the image and its embedded content before sharing or opening.",
          });
        }
      }
    } catch (scanError) {
      if (mountedRef.current) {
        setErrorMessage(scanError instanceof Error ? scanError.message : "Unable to scan this image.");
      }
    } finally {
      scanningRef.current = false;
      if (mountedRef.current) {
        setIsScanning(false);
      }
    }
  };

  const retryScan = () => {
    if (selectedFile) {
      void handleFile(selectedFile);
    }
  };

  const handleInputChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      void handleFile(file);
    }
  };

  const openFilePicker = () => {
    inputRef.current?.click();
  };

  const riskChipColor = useMemo(() => {
    if (!result) {
      return "#7c8aa5";
    }

    const score = result.score;
    if (score >= 50) {
      return "#fb7185";
    }
    if (score >= 25) {
      return "#fbbf24";
    }
    return "#34d399";
  }, [result]);

  return (
    <Box sx={{ minHeight: "calc(100vh - 180px)", pb: { xs: 3, md: 5 } }}>
      <Box sx={{ width: "100%", maxWidth: 760, mx: "auto", pt: { xs: 1, md: 2 } }}>
        <Typography variant="h4" sx={{ fontWeight: 800, fontSize: { xs: "1.75rem", md: "2rem" } }}>
          Image Threat Scanner
        </Typography>

        <Typography sx={{ mt: 2, color: "text.secondary", maxWidth: 760, lineHeight: 1.7, fontSize: { xs: "0.97rem", md: "1.02rem" } }}>
          Upload images to scan for embedded threats, phishing QR codes, and suspicious metadata.
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
          "&:hover": {
            borderColor: "#22d3ee",
            boxShadow: "0 0 0 2px rgba(34, 211, 238, 0.18), 0 28px 70px rgba(0, 0, 0, 0.34)",
          },
        }}
      >
        <Box
          onClick={openFilePicker}
          onDragEnter={(event) => {
            event.preventDefault();
            setIsDragging(true);
          }}
          onDragOver={(event) => {
            event.preventDefault();
            setIsDragging(true);
          }}
          onDragLeave={(event) => {
            event.preventDefault();
            setIsDragging(false);
          }}
          onDrop={(event) => {
            event.preventDefault();
            setIsDragging(false);
            const file = event.dataTransfer.files?.[0];
            if (file) {
              void handleFile(file);
            }
          }}
          sx={{
            minHeight: 132,
            borderRadius: 4,
            border: `2px dashed ${isDragging ? "rgba(45, 212, 191, 0.95)" : "rgba(45, 212, 191, 0.55)"}`,
            bgcolor: isDragging ? "rgba(45, 212, 191, 0.06)" : "rgba(255,255,255,0.012)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            textAlign: "center",
            cursor: "pointer",
            transition: "150ms ease",
            px: 2,
          }}
        >
          <input ref={inputRef} type="file" accept="image/*" hidden onChange={handleInputChange} />

          {selectedFile ? (
            <Stack spacing={1.2} sx={{ alignItems: "center" }}>
              <Box sx={{ display: "inline-flex", alignItems: "center", gap: 1.2, color: "#8ba0c8" }}>
                <InsertPhotoOutlinedIcon sx={{ fontSize: 42 }} />
              </Box>
              <Typography sx={{ color: "text.secondary" }}>
                {isScanning ? "Scanning image..." : selectedFile.name}
              </Typography>
            </Stack>
          ) : (
            <Stack spacing={1.2} sx={{ alignItems: "center" }}>
              <Box sx={{ display: "inline-flex", alignItems: "center", color: "#6f87a8" }}>
                <InsertPhotoOutlinedIcon sx={{ fontSize: 42 }} />
              </Box>
              <Typography sx={{ color: "text.secondary" }}>Upload an image to scan</Typography>
            </Stack>
          )}
        </Box>

        {(errorMessage || result) && <Divider sx={{ my: 3, borderColor: "rgba(255,255,255,0.08)" }} />}

        {errorMessage && (
          <Box>
            <Box sx={{ p: 1.5, borderRadius: 2, bgcolor: "rgba(239, 68, 68, 0.08)", border: "1px solid rgba(239, 68, 68, 0.18)" }}>
              <Typography variant="body2" sx={{ color: "#fca5a5" }}>
                {errorMessage}
              </Typography>
            </Box>

            {selectedFile && !isScanning && (
              <Button
                onClick={retryScan}
                fullWidth
                startIcon={<ReplayRoundedIcon />}
                sx={{
                  mt: 1.5,
                  minHeight: 38,
                  borderRadius: 3,
                  textTransform: "none",
                  fontWeight: 700,
                  fontSize: "0.9rem",
                  color: "#fde68a",
                  bgcolor: "rgba(245, 158, 11, 0.08)",
                  border: "1px solid rgba(245, 158, 11, 0.2)",
                  "&:hover": {
                    bgcolor: "rgba(245, 158, 11, 0.14)",
                    borderColor: "rgba(245, 158, 11, 0.32)",
                  },
                }}
              >
                Retry Scan
              </Button>
            )}
          </Box>
        )}

        {result && (
          <Box sx={{ display: "grid", gap: 2.2 }}>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1.2, alignItems: "center", justifyContent: "space-between" }}>
              <Box>
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                  Scan result
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mt: 0.4 }}>
                  {result.verdict} • Score {result.score}/100
                </Typography>
              </Box>

              <Chip
                label={result.verdict}
                sx={{
                  bgcolor: `${riskChipColor}1a`,
                  color: riskChipColor,
                  border: `1px solid ${riskChipColor}33`,
                  fontWeight: 700,
                }}
              />
            </Box>

            {previewUrl && (
              <Box sx={{ display: "grid", gap: 1.5, gridTemplateColumns: { xs: "1fr", md: "180px 1fr" }, alignItems: "start" }}>
                <Box
                  component="img"
                  src={previewUrl}
                  alt="Uploaded preview"
                  sx={{ width: "100%", borderRadius: 3, border: "1px solid rgba(255,255,255,0.08)" }}
                />

                <Box sx={{ display: "grid", gap: 1 }}>
                  <Box sx={{ p: 1.5, borderRadius: 2, bgcolor: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.05)" }}>
                    <Typography variant="caption" color="text.secondary">
                      File
                    </Typography>
                    <Typography variant="body2">{result.fileName}</Typography>
                  </Box>
                  <Box sx={{ display: "grid", gap: 1, gridTemplateColumns: { xs: "1fr", sm: "1fr 1fr" } }}>
                    <Box sx={{ p: 1.5, borderRadius: 2, bgcolor: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.05)" }}>
                      <Typography variant="caption" color="text.secondary">
                        Type
                      </Typography>
                      <Typography variant="body2">{result.fileType}</Typography>
                    </Box>
                    <Box sx={{ p: 1.5, borderRadius: 2, bgcolor: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.05)" }}>
                      <Typography variant="caption" color="text.secondary">
                        Size
                      </Typography>
                      <Typography variant="body2">{formatBytes(result.fileSize)}</Typography>
                    </Box>
                  </Box>
                  <Box sx={{ display: "grid", gap: 1, gridTemplateColumns: { xs: "1fr", sm: "1fr 1fr" } }}>
                    <Box sx={{ p: 1.5, borderRadius: 2, bgcolor: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.05)" }}>
                      <Typography variant="caption" color="text.secondary">
                        Dimensions
                      </Typography>
                      <Typography variant="body2">{result.width} × {result.height}</Typography>
                    </Box>
                    <Box sx={{ p: 1.5, borderRadius: 2, bgcolor: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.05)" }}>
                      <Typography variant="caption" color="text.secondary">
                        QR code
                      </Typography>
                      <Typography variant="body2">{result.qrData ? "Detected" : "Not detected"}</Typography>
                    </Box>
                  </Box>
                </Box>
              </Box>
            )}

            <Box>
              <Typography variant="caption" sx={{ display: "block", mb: 1, letterSpacing: 1, color: "#6f87a8" }}>
                FINDINGS
              </Typography>
              <Stack spacing={1.2}>
                {result.findings.map((finding) => (
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
                        label={severityLabel(finding.severity)}
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

            {result.exifSummary.length > 0 && (
              <Box>
                <Typography variant="caption" sx={{ display: "block", mb: 1, letterSpacing: 1, color: "#6f87a8" }}>
                  METADATA HIGHLIGHTS
                </Typography>
                <Stack spacing={1.2}>
                  {result.exifSummary.map((item) => (
                    <Box key={item} sx={{ p: 1.4, borderRadius: 2, bgcolor: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.05)" }}>
                      <Typography variant="body2">{item}</Typography>
                    </Box>
                  ))}
                </Stack>
              </Box>
            )}
          </Box>
        )}

        <Stack direction="row" spacing={1.2} sx={{ justifyContent: "center", mt: 3.5, flexWrap: "wrap" }}>
          {[
            "QR decoding",
            "EXIF review",
            "Filename anomaly checks",
            "Dimension validation",
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
          onClick={openFilePicker}
          fullWidth
          startIcon={<CloseRoundedIcon sx={{ transform: "rotate(45deg)" }} />}
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
          Upload another image
        </Button>
      </GlassSurface>
    </Box>
  );
}

export default ImageScanPage;
