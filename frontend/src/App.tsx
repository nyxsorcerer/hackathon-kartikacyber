import { useCallback, useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import {
  BrowserRouter,
  Link,
  NavLink,
  Route,
  Routes,
  useLocation,
} from "react-router-dom";
import {
  Activity,
  ArrowUpRight,
  CircleCheck,
  GitCommitHorizontal,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Menu,
  Radar,
  Search,
  Settings2,
  ShieldAlert,
  Target,
  X,
} from "lucide-react";
import { z } from "zod";
import { mutate, request, setCsrfToken } from "./api";
import { dashboardSchema, sessionSchema, settingsSchema } from "./types";
import type { Session } from "./types";
import { useResource, useShortcut } from "./hooks";
import { isMac, QuickJump } from "./components/QuickJump";
import { Dashboard } from "./pages/Dashboard";
import { Programs } from "./pages/Programs";
import { ProgramForm } from "./pages/ProgramForm";
import { ProgramDetail } from "./pages/ProgramDetail";
import { CommitDetail, Reviews } from "./pages/Commits";
import { CVEs } from "./pages/CVEs";
import { FindingDetail, FindingForm, Findings } from "./pages/Findings";
import { JobDetail, Jobs } from "./pages/Jobs";
import { Settings } from "./pages/Settings";
import { ActionButton, Empty, ErrorNote, Kbd } from "./components/ui";
const navigation = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/programs", label: "Programs", icon: Radar },
  { to: "/reviews", label: "Commit review", icon: GitCommitHorizontal },
  { to: "/cves", label: "CVEs", icon: ShieldAlert },
  { to: "/findings", label: "Findings", icon: Target },
  { to: "/jobs", label: "Jobs", icon: Activity },
] as const;
const noticeSchema = z.object({
  message: z.string(),
  url: z.string().optional(),
});
function Logo() {
  return (
    <span className="brand-mark" aria-hidden="true">
      <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
        <path
          d="M14 2 25 8.5v11L14 26 3 19.5v-11L14 2Z"
          stroke="currentColor"
          strokeWidth="1.3"
        />
        <path d="M8 19V9l12 10V9" stroke="currentColor" strokeWidth="1.6" />
        <circle cx="14" cy="2" r="1.8" fill="currentColor" />
      </svg>
    </span>
  );
}
export function App() {
  return (
    <BrowserRouter>
      <AuthenticatedApp />
    </BrowserRouter>
  );
}
function AuthenticatedApp() {
  const [session, setSession] = useState<Session>();
  const [error, setError] = useState<string>();
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    request("/auth/session", sessionSchema, { signal: controller.signal })
      .then((value) => {
        setCsrfToken(value.csrf_token);
        setSession(value);
        setError(undefined);
      })
      .catch((err: unknown) => {
        if (!controller.signal.aborted)
          setError(
            err instanceof Error
              ? err.message
              : "Unable to verify your session.",
          );
      });
    return () => controller.abort();
  }, [attempt]);
  useEffect(() => {
    const unauthenticated = () => {
      setCsrfToken(undefined);
      setSession({ authenticated: false });
    };
    window.addEventListener("numen:unauthorized", unauthenticated);
    return () =>
      window.removeEventListener("numen:unauthorized", unauthenticated);
  }, []);
  if (error)
    return (
      <div className="auth-screen">
        <div className="login-card">
          <div className="brand">
            <Logo />
            numen<span className="brand-caption">ASSET INTELLIGENCE</span>
          </div>
          <h1>Connection unavailable</h1>
          <ErrorNote>{error}</ErrorNote>
          <button className="primary" onClick={() => setAttempt((n) => n + 1)}>
            Try again
          </button>
        </div>
      </div>
    );
  if (!session)
    return (
      <div className="auth-screen">
        <div className="brand">
          <Logo />
          numen
        </div>
        <p role="status" className="hint">
          Verifying session…
        </p>
      </div>
    );
  if (!session.authenticated)
    return (
      <Login
        onLogin={(value) => {
          setCsrfToken(value.csrf_token);
          setSession(value);
        }}
      />
    );
  return (
    <Shell
      username={session.username || "admin"}
      onLogout={() => {
        setCsrfToken(undefined);
        setSession({ authenticated: false });
      }}
    />
  );
}
function Login({ onLogin }: { onLogin: (session: Session) => void }) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  async function login(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      const session = await mutate("/auth/login", sessionSchema, {
        username: "admin",
        password,
      });
      setPassword("");
      onLogin(session);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to sign in.");
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="auth-screen">
      <div className="auth-ambient" />
      <div className="login-card">
        <div className="brand">
          <Logo />
          numen
        </div>
        <p className="eyebrow">ASSET INTELLIGENCE</p>
        <h1>Welcome back.</h1>
        <p className="page-description">Sign in to your security workspace.</p>
        <form onSubmit={login}>
          <label>
            Operator
            <input value="admin" readOnly autoComplete="username" />
          </label>
          <label>
            Password
            <input
              required
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoFocus
            />
          </label>
          {error && <ErrorNote>{error}</ErrorNote>}
          <button className="primary login-submit" disabled={busy}>
            {busy ? "Signing in…" : "Sign in"}
            <ArrowUpRight size={16} />
          </button>
        </form>
        <div className="login-footer">
          <KeyRound size={15} />
          <p>
            Account setup and recovery are available through the container’s
            operator command.
          </p>
        </div>
      </div>
      <span className="auth-credit">
        SOURCE CHANGES. DEPLOYED EVIDENCE. INFORMED DECISIONS.
      </span>
    </div>
  );
}
function SetupNotice() {
  const settings = useResource("/settings", settingsSchema);
  useEffect(() => {
    const listener = () => settings.refresh();
    window.addEventListener("numen:settings-updated", listener);
    return () => window.removeEventListener("numen:settings-updated", listener);
  }, [settings.refresh]);
  if (!settings.data || settings.data.monitor_interval_days) return null;
  return (
    <div className="setup-notice">
      <KeyRound size={16} aria-hidden="true" />
      <span>
        <strong>Finish initial setup.</strong> Define a monitoring interval and
        connect an agent account when you need one. Programs can be saved in the
        meantime.
      </span>
      <Link className="secondary button" to="/settings?tab=defaults">
        Configure defaults
      </Link>
    </div>
  );
}
function useMediaQuery(query: string) {
  const supported = typeof window.matchMedia === "function";
  const [matches, setMatches] = useState(
    () => supported && window.matchMedia(query).matches,
  );
  useEffect(() => {
    if (!supported) return;
    const media = window.matchMedia(query);
    const listener = () => setMatches(media.matches);
    listener();
    media.addEventListener("change", listener);
    return () => media.removeEventListener("change", listener);
  }, [query, supported]);
  return matches;
}
const slashKey = ["/"];
/** Counts shown next to navigation items; failures leave the nav unadorned. */
function useNavCounts() {
  const dashboard = useResource("/dashboard", dashboardSchema, 30000);
  const { refresh } = dashboard;
  useEffect(() => {
    window.addEventListener("numen:notice", refresh);
    window.addEventListener("numen:changed", refresh);
    return () => {
      window.removeEventListener("numen:notice", refresh);
      window.removeEventListener("numen:changed", refresh);
    };
  }, [refresh]);
  const data = dashboard.data;
  return {
    "/reviews": data?.security_reviews,
    "/jobs": data?.running_jobs,
  } as Partial<Record<string, number>>;
}
function Shell({
  username,
  onLogout,
}: {
  username: string;
  onLogout: () => void;
}) {
  const location = useLocation();
  const mobile = useMediaQuery("(max-width: 900px)");
  const [mobileOpen, setMobileOpen] = useState(false);
  const [notice, setNotice] = useState<{ message: string; url?: string }>();
  const counts = useNavCounts();
  const sidebar = useRef<HTMLElement>(null);
  const [quickJump, setQuickJump] = useState(false);
  useEffect(() => {
    const listener = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setQuickJump((open) => !open);
      }
    };
    window.addEventListener("keydown", listener);
    return () => window.removeEventListener("keydown", listener);
  }, []);
  const openQuickJump = useCallback(() => setQuickJump(true), []);
  useShortcut(slashKey, openQuickJump, !quickJump);
  useEffect(() => {
    const listener = (e: Event) => {
      if (e instanceof CustomEvent) {
        const result = noticeSchema.safeParse(e.detail);
        if (result.success) setNotice(result.data);
      }
    };
    window.addEventListener("numen:notice", listener);
    return () => window.removeEventListener("numen:notice", listener);
  }, []);
  useEffect(() => {
    if (!notice) return;
    const timeout = setTimeout(() => setNotice(undefined), 12000);
    return () => clearTimeout(timeout);
  }, [notice]);
  useEffect(() => {
    if (!mobileOpen) return;
    sidebar.current?.querySelector<HTMLElement>("a")?.focus();
    const listener = (e: KeyboardEvent) => {
      if (e.key === "Escape") setMobileOpen(false);
    };
    window.addEventListener("keydown", listener);
    return () => window.removeEventListener("keydown", listener);
  }, [mobileOpen]);
  const label = location.pathname.startsWith("/settings")
    ? "Settings"
    : location.pathname.startsWith("/commits")
      ? "Commit review"
      : navigation.find(
          (item) => item.to !== "/" && location.pathname.startsWith(item.to),
        )?.label || "Dashboard";
  const close = () => setMobileOpen(false);
  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      {mobileOpen && (
        <button
          className="nav-scrim"
          aria-label="Close navigation"
          tabIndex={-1}
          onClick={close}
        />
      )}
      <aside
        ref={sidebar}
        className={`sidebar ${mobileOpen ? "open" : ""}`}
        inert={mobile && !mobileOpen}
      >
        <div className="sidebar-top">
          <Link className="brand" to="/" onClick={close}>
            <Logo />
            numen
          </Link>
          <button
            className="icon-button mobile-only"
            aria-label="Close navigation"
            onClick={close}
          >
            <X size={18} />
          </button>
        </div>
        <nav aria-label="Main navigation">
          {navigation.map((item) => {
            const count = counts[item.to];
            return (
              <NavLink
                end={item.to === "/"}
                key={item.to}
                to={item.to}
                onClick={close}
              >
                <item.icon size={17} aria-hidden="true" />
                <span>{item.label}</span>
                {!!count && (
                  <span
                    className="nav-count"
                    aria-label={
                      item.to === "/jobs"
                        ? `${count} active`
                        : `${count} awaiting review`
                    }
                  >
                    {count}
                  </span>
                )}
              </NavLink>
            );
          })}
        </nav>
        <div className="sidebar-bottom">
          <NavLink to="/settings" onClick={close}>
            <Settings2 size={17} aria-hidden="true" />
            <span>Settings</span>
          </NavLink>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="topbar-start">
            <button
              className="icon-button mobile-nav-toggle"
              aria-label="Open navigation"
              aria-expanded={mobileOpen}
              onClick={() => setMobileOpen(true)}
            >
              <Menu size={19} />
            </button>
            <span className="topbar-section">{label}</span>
          </div>
          <button
            type="button"
            className="quick-jump-trigger"
            aria-keyshortcuts={isMac ? "Meta+K /" : "Control+K /"}
            onClick={openQuickJump}
          >
            <Search size={15} aria-hidden="true" />
            <span className="quick-jump-label">Search or jump to…</span>
            <Kbd>{isMac ? "⌘K" : "Ctrl K"}</Kbd>
          </button>
          <div className="operator-menu">
            <span className="operator-avatar" aria-hidden="true">
              {username.slice(0, 1).toUpperCase()}
            </span>
            <span className="operator-name">{username}</span>
            <ActionButton
              className="icon-button"
              title="Sign out"
              onAction={async () => {
                await mutate("/auth/logout", z.unknown());
                onLogout();
              }}
            >
              <span className="sr-only">Sign out</span>
              <LogOut size={16} aria-hidden="true" />
            </ActionButton>
          </div>
        </header>
        <main id="main-content" tabIndex={-1}>
          <SetupNotice />
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/programs" element={<Programs />} />
            <Route path="/programs/new" element={<ProgramForm />} />
            <Route path="/programs/:id/edit" element={<ProgramForm />} />
            <Route path="/programs/:id" element={<ProgramDetail />} />
            <Route path="/reviews" element={<Reviews />} />
            <Route path="/commits/:id" element={<CommitDetail />} />
            <Route path="/cves" element={<CVEs />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/findings/new" element={<FindingForm />} />
            <Route path="/findings/:id/edit" element={<FindingForm />} />
            <Route path="/findings/:id" element={<FindingDetail />} />
            <Route path="/jobs" element={<Jobs />} />
            <Route path="/jobs/:id" element={<JobDetail />} />
            <Route path="/settings" element={<Settings />} />
            <Route
              path="*"
              element={
                <Empty
                  title="Page not found"
                  description="This address does not match a page in the dashboard."
                  action={
                    <Link className="secondary button" to="/">
                      Return to dashboard
                    </Link>
                  }
                />
              }
            />
          </Routes>
        </main>
        {quickJump && <QuickJump onClose={() => setQuickJump(false)} />}
        {notice && (
          <div className="toast" role="status">
            <CircleCheck size={17} aria-hidden="true" />
            <span>{notice.message}</span>
            {notice.url && (
              <Link to={notice.url} onClick={() => setNotice(undefined)}>
                View job <ArrowUpRight size={14} aria-hidden="true" />
              </Link>
            )}
            <button
              className="icon-button"
              aria-label="Dismiss notification"
              onClick={() => setNotice(undefined)}
            >
              <X size={16} />
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
