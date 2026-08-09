import CloudUploadRoundedIcon from "@mui/icons-material/CloudUploadRounded";

import {
  Avatar,
  Box,
  Button,
  Stack,
  Typography,
  LinearProgress,
  Snackbar,
  Alert,
} from "@mui/material";

import DashboardWidget from "../../../components/ui/DashboardWidget/DashboardWidget";
import ingestionService from "../services/ingestionService";
import { useRef, useState } from "react";

function UploadCard() {
  const inputRef = useRef<HTMLInputElement | null>(null);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [snack, setSnack] = useState<{open:boolean, severity:'success'|'error', message:string}>({open:false,severity:'success',message:''});

  const handleSelect = () => {
    inputRef.current?.click();
  };

  const handleFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (!f) return;

    setLoading(true);
    setProgress(0);

    try {
      const res = await ingestionService.upload(f, (p) => setProgress(p));
      console.log('upload success', res);
      setSnack({open:true,severity:'success',message:'Dataset uploaded successfully.'});
      // After success, refresh the page to let components reload datasets
      setTimeout(() => window.location.reload(), 800);
    } catch (err: any) {
      console.error('upload failed', err);
      setSnack({open:true,severity:'error',message:`Upload failed: ${err?.message ?? err}`});
    } finally {
      setLoading(false);
      setProgress(0);
      if (inputRef.current) inputRef.current.value = "";
    }
  };

  return (
    <DashboardWidget
      title="Upload Security Logs"
      subtitle="Import datasets into the ingestion pipeline"
      height={340}
    >
      <Stack
        justifyContent="center"
        alignItems="center"
        spacing={3}
        height="100%"
      >
        <input ref={inputRef} type="file" accept=".csv,.json,.evtx,.txt" style={{display:'none'}} onChange={handleFile} />

        <Avatar
          sx={{
            width: 72,
            height: 72,
            bgcolor: "#E0F2FE",
            color: "#0284C7",
          }}
        >
          <CloudUploadRoundedIcon fontSize="large" />
        </Avatar>

        <Typography
          variant="h6"
          fontWeight={600}
        >
          Drag & Drop Files
        </Typography>

        <Typography
          color="text.secondary"
          textAlign="center"
        >
          Upload Windows, Linux, Firewall,
          Authentication or Threat Intelligence logs.
        </Typography>

        <Button
          variant="contained"
          size="large"
          onClick={handleSelect}
          disabled={loading}
        >
          {loading ? `Uploading ${progress}%` : 'Select Files'}
        </Button>

        {loading && <Box sx={{ width: '100%', mt: 2 }}><LinearProgress variant="determinate" value={progress} /></Box>}

        <Snackbar open={snack.open} autoHideDuration={4000} onClose={() => setSnack(s=>({...s,open:false}))}>
          <Alert severity={snack.severity} onClose={() => setSnack(s=>({...s,open:false}))}>{snack.message}</Alert>
        </Snackbar>
      </Stack>
    </DashboardWidget>
  );
}

export default UploadCard;