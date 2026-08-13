import { useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import { authService } from "./authService";
import LandingPage from "../pages/LandingPage";

function RootRedirect() {
  const [checked, setChecked] = useState(false);
  const [authenticated, setAuthenticated] = useState(false);

  useEffect(() => {
    authService.getCurrentUser().then((user) => {
      setAuthenticated(Boolean(user));
      setChecked(true);
    });
  }, []);

  if (!checked) return null;
  if (authenticated) return <Navigate to="/dashboard" replace />;

  return <LandingPage />;
}

export default RootRedirect;