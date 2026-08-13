import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";

import AppLayout from "../layouts/AppLayout";
import LandingPage from "../pages/LandingPage";
import SignInPage from "../pages/SignInPage";
import SignUpPage from "../pages/SignUpPage";
import ProfilePage from "../pages/ProfilePage";
import RequireAuth from "../auth/RequireAuth";
import DashboardPage from "../modules/dashboard/DashboardPage";
import AnalyticsPage from "../modules/analytics/AnalyticsPage";
import DataIngestionPage from "../modules/ingestion/DataIngestionPage";
import SettingsPage from "../modules/settings/SettingsPage";
import AssistantPage from "../modules/assistant/AssistantPage";
import PlaceholderFeaturePage from "../modules/shared/PlaceholderFeaturePage";
import LiveApiPage from "../modules/liveApi/LiveApiPage";
import RestApiPage from "../modules/restApi/RestApiPage";
import ImageScanPage from "../modules/imageScan/ImageScanPage";
import BarcodePage from "../modules/barcode/BarcodePage";
import NmapPage from "../modules/nmap/NmapPage";
import StatisticsPage from "../modules/statistics/StatisticsPage";
import ApiKeysPage from "../modules/apiKeys/ApiKeysPage";
import OpenVasPage from "../modules/openvas/OpenVasPage";
import NiktoPage from "../modules/nikto/NiktoPage";
import ToolControlPage from "../modules/shared/ToolControlPage";
import ThreatDetectionPage from "../modules/detection/ThreatDetectionPage";
import IncidentResponsePage from "../modules/incidents/IncidentResponsePage";
import ThreatIntelligencePage from "../modules/intelligence/ThreatIntelligencePage";
import ReportsPage from "../modules/reports/ReportsPage";
import SecuritySourcesPage from "../modules/security/SecuritySourcesPage";
import SIEMMonitoringPage from "../modules/siem/SIEMMonitoringPage";
import RootRedirect from "../auth/RootRedirect";

export default function AppRouter() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<RootRedirect />} />
        <Route path="/sign-in" element={<SignInPage />} />
        <Route path="/sign-up" element={<SignUpPage />} />

        <Route element={<RequireAuth><AppLayout /></RequireAuth>}>
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/analytics" element={<AnalyticsPage />} />
          <Route path="/ai-assistant" element={<AssistantPage />} />
          <Route path="/static-data" element={<DataIngestionPage />} />
          <Route path="/live-api" element={<LiveApiPage />} />
          <Route path="/rest-api" element={<RestApiPage />} />
          <Route path="/image-scan" element={<ImageScanPage />} />
          <Route path="/barcode" element={<BarcodePage />} />
          <Route path="/nmap" element={<NmapPage />} />
          <Route path="/statistics" element={<StatisticsPage />} />
          <Route path="/api-keys" element={<ApiKeysPage />} />
          <Route path="/profile" element={<ProfilePage />} />
          <Route path="/threat-detection" element={<ThreatDetectionPage />} />
          <Route path="/incident-response" element={<IncidentResponsePage />} />
          <Route path="/threat-intelligence" element={<ThreatIntelligencePage />} />
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/security-sources" element={<SecuritySourcesPage />} />
          <Route path="/siem-monitoring" element={<SIEMMonitoringPage />} />
          <Route path="/ai-summary" element={<PlaceholderFeaturePage title="AI Summary" description="Summarize current incidents, investigation progress, and response posture." stats={[{label:"Summaries", value:"48", detail:"last 24h"},{label:"Coverage", value:"89%", detail:"critical cases"},{label:"Quality", value:"4.8/5", detail:"analyst rating"}]} badge="Summary" />} />
          <Route path="/ai-recs" element={<PlaceholderFeaturePage title="AI Recs" description="Review AI-generated recommendations and operational next steps." stats={[{label:"Recommendations", value:"24", detail:"ranked"},{label:"Accepted", value:"68%", detail:"auto-accepted"},{label:"Priority", value:"High", detail:"escalation queue"}]} badge="Recs" />} />
          <Route path="/vulnerability-assessment" element={<PlaceholderFeaturePage title="Vulnerability Assessment" description="Monitor known weaknesses and remediation tracking across all monitors." stats={[{label:"Assets reviewed", value:"392", detail:"active scope"},{label:"Critical vulns", value:"11", detail:"requires patching"},{label:"Remediated", value:"76%", detail:"this quarter"}]} badge="Vulns" />} />
          <Route path="/openvas" element={<OpenVasPage />} />
          <Route path="/nikto" element={<NiktoPage />} />
          <Route path="/penetration-testing" element={<PlaceholderFeaturePage title="Penetration Testing" description="Coordinate penetration exercises, scope, and recommended testing modules." stats={[{label:"Tests run", value:"8", detail:"current cycle"},{label:"Open findings", value:"14", detail:"triage backlog"},{label:"Coverage", value:"92%", detail:"critical paths"}]} badge="Pentest" />} />
          <Route path="/metasploit" element={<ToolControlPage title="Metasploit Framework" description="Exploit testing framework for penetration testing." category="Penetration Testing" docsUrl="https://docs.metasploit.com/" />} />
          <Route path="/sqlmap" element={<ToolControlPage title="SQLmap" description="Automated SQL injection testing tool." category="Penetration Testing" docsUrl="https://github.com/sqlmapproject/sqlmap/wiki" />} />
          <Route path="/john-the-ripper" element={<ToolControlPage title="John the Ripper" description="Password strength testing tool." category="Penetration Testing" docsUrl="https://www.openwall.com/john/doc/" />} />
          <Route path="/web-application-security" element={<PlaceholderFeaturePage title="Web Application Security" description="Review web app inspections, findings, and posture changes." stats={[{label:"Sites tested", value:"27", detail:"this month"},{label:"Critical flaws", value:"5", detail:"needs remediation"},{label:"Coverage", value:"88%", detail:"automation"}]} badge="WAS" />} />
          <Route path="/owasp" element={<ToolControlPage title="OWASP ZAP" description="Automated and manual web application scanning." category="Web Application Security" docsUrl="https://www.zaproxy.org/docs/" ready />} />
          <Route path="/wapiti" element={<ToolControlPage title="Wapiti" description="Detects web application vulnerabilities." category="Web Application Security" docsUrl="https://wapiti-scanner.github.io/" />} />
          <Route path="/siem-monitoring-tools" element={<PlaceholderFeaturePage title="SIEM & Monitoring" description="Coordinate monitoring tooling health, event volume, and detections." stats={[{label:"Event volume", value:"1.1M", detail:"today"},{label:"Rules enabled", value:"186", detail:"active"},{label:"Latency", value:"2.3s", detail:"ingestion"}]} badge="SIEM" />} />
          <Route path="/wazuh" element={<ToolControlPage title="Wazuh" description="Open-source SIEM/XDR platform." category="SIEM & Monitoring" docsUrl="https://documentation.wazuh.com/" ready />} />
          <Route path="/snort" element={<ToolControlPage title="Snort" description="Network IDS/IPS monitoring system." category="SIEM & Monitoring" docsUrl="https://docs.snort.org/" />} />
          <Route path="/forensics" element={<PlaceholderFeaturePage title="Digital Forensics" description="Coordinate forensic evidence review, chain of custody, and triage tasks." stats={[{label:"Cases", value:"9", detail:"open"},{label:"Evidence", value:"36", detail:"processed"},{label:"Backlog", value:"4", detail:"queued"}]} badge="Forensics" />} />
          <Route path="/autopsy" element={<ToolControlPage title="Autopsy" description="GUI-based digital forensic analysis platform." category="Digital Forensics" docsUrl="https://www.autopsy.com/documentation/" />} />
          <Route path="/volatility" element={<ToolControlPage title="Volatility" description="Memory analysis framework for incident response." category="Digital Forensics" docsUrl="https://volatility3.readthedocs.io/" />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Route>

        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
