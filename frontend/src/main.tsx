import "./auth/amplifyConfig";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import App from "./app/App";
import ErrorBoundary from "./components/ErrorBoundary";
import { ThemeModeProvider } from "./theme/ThemeModeContext";

import "./index.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ErrorBoundary>
      <ThemeModeProvider>
        <App />
      </ThemeModeProvider>
    </ErrorBoundary>
  </StrictMode>
);
