import DescriptionOutlinedIcon from "@mui/icons-material/DescriptionOutlined";
import { useRef, useState } from "react";

import {
  Alert,
  Box,
  Button,
  LinearProgress,
  Snackbar,
  Typography,
} from "@mui/material";

import ingestionService from "./services/ingestionService";

type UploadNotice = {
  message: string;
  severity: "success" | "error";
};

function DataIngestionPage() {
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [notice, setNotice] = useState<UploadNotice | null>(null);

  const handleUpload = async (file: File) => {
    console.log("Uploading...");
    setIsUploading(true);
    setUploadProgress(0);
    setNotice(null);

    try {
      const response = await ingestionService.upload(file, setUploadProgress);
      setNotice({
        severity: "success",
        message: response.message || "Dataset uploaded successfully.",
      });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "The file could not be uploaded.";
      setNotice({ severity: "error", message });
    } finally {
      setIsUploading(false);
      setUploadProgress(0);
      if (fileInputRef.current) {
        fileInputRef.current.value = "";
      }
    }
  };

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];

    if (!file) {
      return;
    }

    console.log("File selected");
    console.log(file);
    setSelectedFile(file);
    void handleUpload(file);
  };

  return (
    <Box
      sx={{
        minHeight: "calc(100vh - 180px)",
        display: "flex",
        alignItems: "flex-start",
        justifyContent: "center",
        pt: { xs: 2, md: 4 },
        px: { xs: 2, md: 3 },
      }}
    >
      <Box sx={{ width: "100%", maxWidth: 860 }}>
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 2, fontSize: { xs: "1.6rem", md: "1.9rem" } }}>
          Static Data Upload
        </Typography>

        <Typography sx={{ color: "text.secondary", mb: 4, maxWidth: 700, lineHeight: 1.7, fontSize: { xs: "0.95rem", md: "1rem" } }}>
          Upload CSV or JSON threat data files to visualize on the dashboard.
        </Typography>

        <Box
          onClick={() => {
            if (!isUploading) {
              fileInputRef.current?.click();
            }
          }}
          sx={{
            minHeight: { xs: 190, md: 156 },
            borderRadius: 0,
            border: "2px solid rgba(148, 163, 184, 0.22)",
            bgcolor: "rgba(255,255,255,0.02)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            textAlign: "center",
            px: 2,
            cursor: "pointer",
            overflow: "hidden",
            transition: "border-color 180ms ease, box-shadow 180ms ease, background-color 180ms ease",
            "&:hover": {
              borderColor: "#22d3ee",
              bgcolor: "rgba(34, 211, 238, 0.05)",
              boxShadow: "0 0 0 2px rgba(34, 211, 238, 0.18)",
            },
          }}
        >
          <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", maxWidth: 420 }}>
            <DescriptionOutlinedIcon sx={{ fontSize: 44, color: "text.secondary", mb: 1 }} />
            <Typography sx={{ color: "text.secondary", fontSize: { xs: "0.95rem", md: "1rem" } }}>
              Drop CSV or JSON files here
            </Typography>
            <Typography variant="body2" sx={{ color: "text.secondary", mt: 0.7 }}>
              or click to browse
            </Typography>
            <input
              ref={fileInputRef}
              type="file"
              accept=".csv,.json"
              hidden
              disabled={isUploading}
              onChange={handleFileSelect}
            />
            <Button
              variant="contained"
              disabled={isUploading}
              onClick={(event) => {
                event.stopPropagation();
                fileInputRef.current?.click();
              }}
              sx={{ mt: 2.2, minWidth: 140, whiteSpace: "nowrap" }}
            >
              {isUploading ? "Uploading..." : "Browse Files"}
            </Button>

            {selectedFile && (
              <Typography variant="body2" sx={{ color: "text.secondary", mt: 1.5 }}>
                {selectedFile.name}
              </Typography>
            )}

            {isUploading && (
              <Box sx={{ width: "100%", mt: 2 }}>
                <LinearProgress
                  variant={uploadProgress > 0 ? "determinate" : "indeterminate"}
                  value={uploadProgress}
                />
              </Box>
            )}
          </Box>
        </Box>
      </Box>

      <Snackbar
        open={notice !== null}
        autoHideDuration={5000}
        onClose={() => setNotice(null)}
      >
        <Alert
          severity={notice?.severity || "success"}
          onClose={() => setNotice(null)}
          variant="filled"
        >
          {notice?.message}
        </Alert>
      </Snackbar>
    </Box>
  );
}

export default DataIngestionPage;
