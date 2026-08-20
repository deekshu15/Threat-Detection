import { useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import { authService } from "./authService";

function RequireAuth({ children }: { children: React.ReactNode }) {
  const [checked, setChecked] = useState(false);
  const [authenticated, setAuthenticated] = useState(false);

  useEffect(() => {
    authService.getCurrentUser().then((user) => {
      setAuthenticated(Boolean(user));
      setChecked(true);
    });
  }, []);

  if (import.meta.env.DEV) {
    return <>{children}</>;
  }

  if (!checked) return null;
  if (!authenticated) return <Navigate to="/sign-in" replace />;

  return <>{children}</>;
}

export default RequireAuth;