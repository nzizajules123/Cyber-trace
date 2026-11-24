import { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";

import Icon from "./Icon.jsx";
import { useAuth } from "../context/AuthContext.jsx";
import { confirmPasswordRecovery, requestPasswordRecovery } from "../services/forensicsApi.js";

function AuthShell({ title, subtitle, children }) {
  return (
    <div className="auth-shell">
      <section className="panel auth-card">
        <div className="auth-brand">
          <span className="brand-mark"><Icon name="shield" size={20} /></span>
          <span className="brand-name">CYBER<span>TRACE</span></span>
        </div>
        <h1>{title}</h1>
        <p className="auth-subtitle">{subtitle}</p>
        {children}
      </section>
    </div>
  );
}

export function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const from = location.state?.from || "/";

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [needsMfa, setNeedsMfa] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (event) => {
    event.preventDefault();
    setSubmitting(true);
    setError("");
    try {
      await login({ email, password, totpCode: totpCode || undefined });
      navigate(from, { replace: true });
    } catch (cause) {
      const msg = cause instanceof Error ? cause.message : "Sign in failed.";
      if (msg.toLowerCase().includes("mfa")) setNeedsMfa(true);
      setError(msg);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AuthShell
      title="Sign in to CyberTrace"
      subtitle="Authorized digital forensics & cyber investigation workspace."
    >
      {error && (
        <div className="dashboard-error" role="alert">
          <Icon name="findings" size={16} />
          <div><strong>Authentication failed</strong><p>{error}</p></div>
        </div>
      )}
      <form className="case-form" onSubmit={handleSubmit}>
        <label>
          <span>Email address</span>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            autoComplete="email"
            placeholder="investigator@organization.org"
          />
        </label>
        <label>
          <span>Password</span>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            autoComplete="current-password"
          />
        </label>
        {needsMfa && (
          <label>
            <span>6-digit MFA code</span>
            <input
              type="text"
              inputMode="numeric"
              value={totpCode}
              onChange={(e) => setTotpCode(e.target.value)}
              placeholder="123456"
              maxLength={8}
            />
          </label>
        )}
        <button className="primary-button auth-submit" type="submit" disabled={submitting}>
          {submitting ? "Signing in…" : "Sign in"}
        </button>
      </form>
      <div className="auth-links">
        <Link to="/register">Create investigator account</Link>
        <Link to="/recover-password">Forgot password?</Link>
      </div>
    </AuthShell>
  );
}

export function RegisterPage() {
  const { register } = useAuth();
  const navigate = useNavigate();

  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [organizationName, setOrganizationName] = useState("");
  const [organizationSlug, setOrganizationSlug] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (event) => {
    event.preventDefault();
    setSubmitting(true);
    setError("");
    try {
      await register({
        fullName,
        email,
        password,
        organizationName: organizationSlug ? "" : organizationName,
        organizationSlug: organizationSlug || "",
      });
      navigate("/", { replace: true });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Registration failed.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AuthShell
      title="Create Investigator Account"
      subtitle="Initialize a new forensic organization or join an authorized organization by slug."
    >
      {error && (
        <div className="dashboard-error" role="alert">
          <Icon name="findings" size={16} />
          <div><strong>Registration failed</strong><p>{error}</p></div>
        </div>
      )}
      <form className="case-form" onSubmit={handleSubmit}>
        <label>
          <span>Full name</span>
          <input value={fullName} onChange={(e) => setFullName(e.target.value)} required minLength={2} />
        </label>
        <label>
          <span>Email address</span>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="email" />
        </label>
        <label>
          <span>Password (min. 8 characters, Argon2id hashed)</span>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            minLength={8}
            autoComplete="new-password"
          />
        </label>
        <label>
          <span>New organization name</span>
          <input
            value={organizationName}
            onChange={(e) => setOrganizationName(e.target.value)}
            placeholder="e.g. Acme Forensics Lab"
            disabled={Boolean(organizationSlug)}
          />
        </label>
        <label>
          <span>Or join existing organization (slug, optional)</span>
          <input
            value={organizationSlug}
            onChange={(e) => setOrganizationSlug(e.target.value)}
            placeholder="Optional organization slug"
          />
        </label>
        <button className="primary-button auth-submit" type="submit" disabled={submitting}>
          {submitting ? "Creating account…" : "Create account"}
        </button>
      </form>
      <div className="auth-links">
        <Link to="/login">Already have an account? Sign in</Link>
      </div>
    </AuthShell>
  );
}

export function RecoverPasswordPage() {
  const [step, setStep] = useState("request");
  const [email, setEmail] = useState("");
  const [token, setToken] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const handleRequest = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const res = await requestPasswordRecovery(email);
      setNotice(
        res.localRecoveryToken
          ? `${res.message} Local lab token: ${res.localRecoveryToken}`
          : res.message,
      );
      if (res.localRecoveryToken) setToken(res.localRecoveryToken);
      setStep("confirm");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Recovery request failed.");
    } finally {
      setBusy(false);
    }
  };

  const handleConfirm = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const res = await confirmPasswordRecovery({ token, newPassword });
      setNotice(res.message);
      setStep("done");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Password reset failed.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthShell title="Password Recovery" subtitle="Reset your investigator credentials securely.">
      {notice && <div className="case-success-notice" role="status">{notice}</div>}
      {error && (
        <div className="dashboard-error" role="alert">
          <Icon name="findings" size={16} />
          <div><strong>Recovery error</strong><p>{error}</p></div>
        </div>
      )}
      {step === "request" ? (
        <form className="case-form" onSubmit={handleRequest}>
          <label>
            <span>Account email</span>
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          </label>
          <button className="primary-button auth-submit" type="submit" disabled={busy}>
            {busy ? "Requesting…" : "Request recovery token"}
          </button>
        </form>
      ) : step === "confirm" ? (
        <form className="case-form" onSubmit={handleConfirm}>
          <label>
            <span>Recovery token</span>
            <input value={token} onChange={(e) => setToken(e.target.value)} required />
          </label>
          <label>
            <span>New password (min. 8 characters)</span>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
              minLength={8}
            />
          </label>
          <button className="primary-button auth-submit" type="submit" disabled={busy}>
            {busy ? "Updating…" : "Set new password"}
          </button>
        </form>
      ) : null}
      <div className="auth-links">
        <Link to="/login">Back to sign in</Link>
      </div>
    </AuthShell>
  );
}
