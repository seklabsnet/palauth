"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useSyncExternalStore,
} from "react";
import * as api from "./api";

interface AuthState {
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthState>({
  isAuthenticated: false,
  login: async () => {},
  logout: () => {},
});

function subscribeToStorage(callback: () => void) {
  window.addEventListener("storage", callback);
  return () => window.removeEventListener("storage", callback);
}

function getAuthSnapshot() {
  return api.isAuthenticated() && !api.isTokenExpired();
}

function getServerSnapshot() {
  return false;
}

const EXPIRY_CHECK_INTERVAL = 30_000; // 30 seconds

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const isAuthenticated = useSyncExternalStore(
    subscribeToStorage,
    getAuthSnapshot,
    getServerSnapshot
  );

  const login = useCallback(async (email: string, password: string) => {
    await api.adminLogin(email, password);
    window.dispatchEvent(new Event("storage"));
  }, []);

  const logout = useCallback(() => {
    api.adminLogout();
    window.dispatchEvent(new Event("storage"));
    window.location.href = "/login";
  }, []);

  // Periodically check JWT expiry and auto-logout.
  useEffect(() => {
    if (!isAuthenticated) return;

    function checkExpiry() {
      if (api.isTokenExpired()) {
        api.adminLogout();
        window.dispatchEvent(new Event("storage"));
        window.location.href = "/login";
      }
    }

    const interval = setInterval(checkExpiry, EXPIRY_CHECK_INTERVAL);

    // Also check on window focus (user returns to tab).
    window.addEventListener("focus", checkExpiry);

    return () => {
      clearInterval(interval);
      window.removeEventListener("focus", checkExpiry);
    };
  }, [isAuthenticated]);

  return (
    <AuthContext.Provider value={{ isAuthenticated, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
