import { createContext, useCallback, useContext, useEffect, useState } from "react";

import { apiRequest, clearStoredToken, getStoredToken, setStoredToken } from "../services/apiClient.js";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [auth, setAuth] = useState(null);
  const [loading, setLoading] = useState(true);

  const loadSession = useCallback(async () => {
    const token = getStoredToken();
    if (!token) {
      setAuth(null);
      setLoading(false);
      return;
    }
    try {
      const me = await apiRequest("/api/v1/auth/me", { skipAuthEvent: true });
      setAuth(me);
    } catch {
      clearStoredToken();
      setAuth(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadSession();
  }, [loadSession]);

  useEffect(() => {
    const handleUnauthorized = () => {
      clearStoredToken();
      setAuth(null);
    };
    window.addEventListener("cybertrace:unauthorized", handleUnauthorized);
    return () => window.removeEventListener("cybertrace:unauthorized", handleUnauthorized);
  }, []);

  const login = async ({ email, password, totpCode }) => {
    const payload = await apiRequest("/api/v1/auth/login", {
      method: "POST",
      skipAuthEvent: true,
      body: JSON.stringify({
        email,
        password,
        ...(totpCode ? { totpCode } : {}),
      }),
    });
    setStoredToken(payload.accessToken);
    await loadSession();
    return payload;
  };

  const register = async ({ email, fullName, password, organizationName, organizationSlug }) => {
    const payload = await apiRequest("/api/v1/auth/register", {
      method: "POST",
      skipAuthEvent: true,
      body: JSON.stringify({
        email,
        fullName,
        password,
        ...(organizationName ? { organizationName } : {}),
        ...(organizationSlug ? { organizationSlug } : {}),
      }),
    });
    setStoredToken(payload.accessToken);
    await loadSession();
    return payload;
  };

  const logout = async () => {
    try {
      await apiRequest("/api/v1/auth/logout", { method: "POST", skipAuthEvent: true });
    } catch {
      // always clear local session even if server already expired it
    }
    clearStoredToken();
    setAuth(null);
  };

  return (
    <AuthContext.Provider
      value={{
        auth,
        user: auth?.user ?? null,
        organization: auth?.organization ?? null,
        role: auth?.role ?? null,
        isAuthenticated: Boolean(auth?.user),
        loading,
        login,
        register,
        logout,
        refreshAuth: loadSession,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
