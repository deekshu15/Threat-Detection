import ChevronRightRoundedIcon from "@mui/icons-material/ChevronRightRounded";

import {
  Breadcrumbs as MuiBreadcrumbs,
  Link,
  Typography,
} from "@mui/material";

import { Link as RouterLink, useLocation } from "react-router-dom";

function Breadcrumbs() {
  const location = useLocation();

  const pathnames = location.pathname
    .split("/")
    .filter(Boolean);

  const labels: Record<string, string> = {
    dashboard: "Dashboard",
    "static-data": "Static Data",
    "live-api": "Live API",
    "rest-api": "REST API",
    "image-scan": "Image Scan",
    barcode: "Barcode",
    nmap: "Nmap",
    statistics: "Statistics",
    "ai-assistant": "AI Assistant",
    "api-keys": "API Keys",
    "ai-summary": "AI Summary",
    "ai-recs": "AI Recs",
    "vulnerability-assessment": "Vulnerability Assessment",
    openvas: "OpenVAS",
    nikto: "Nikto",
    "penetration-testing": "Penetration Testing",
    metasploit: "Metasploit Framework",
    sqlmap: "SQLmap",
    "john-the-ripper": "John the Ripper",
    "web-application-security": "Web Application Security",
    owasp: "OWASP ZAP",
    wapiti: "Wapiti",
    "siem-monitoring-tools": "SIEM & Monitoring",
    wazuh: "Wazuh",
    snort: "Snort",
    forensics: "Digital Forensics",
    autopsy: "Autopsy",
    volatility: "Volatility",
    settings: "Settings",
  };

  if (location.pathname === "/dashboard") {
    return (
      <Typography color="text.primary" sx={{ mb: 3 }}>
        Dashboard
      </Typography>
    );
  }

  return (
    <MuiBreadcrumbs
      separator={<ChevronRightRoundedIcon fontSize="small" />}
      sx={{ mb: 3 }}
    >
      <Link component={RouterLink} underline="hover" color="inherit" to="/dashboard">
        Dashboard
      </Link>

      {pathnames.map((value, index) => {
        const to = "/" + pathnames.slice(0, index + 1).join("/");
        const isLast = index === pathnames.length - 1;
        const label = labels[value] ?? value.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());

        return isLast ? (
          <Typography key={to} color="text.primary">
            {label}
          </Typography>
        ) : (
          <Link key={to} component={RouterLink} underline="hover" color="inherit" to={to}>
            {label}
          </Link>
        );
      })}
    </MuiBreadcrumbs>
  );
}

export default Breadcrumbs;