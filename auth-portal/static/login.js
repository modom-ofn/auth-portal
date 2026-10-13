// /static/login.js
(() => {
  let lastAuthRedirect = "/home";
  let oauthCancelled = false;
  let activeLoginCleanup = () => {};

  function safeRedirect(path) {
    try {
      const dest = new URL(String(path || ""), globalThis.location.origin);
      if (dest.origin !== globalThis.location.origin) return null;
      if (dest.protocol !== "http:" && dest.protocol !== "https:") return null;
      return dest.pathname + dest.search + dest.hash;
    } catch {
      return null;
    }
  }

  function continueTargetFromLocation() {
    try {
      const params = new URLSearchParams(globalThis.location.search || "");
      const next = params.get("next") || sessionStorage.getItem("authportal.oauth.next");
      const safe = safeRedirect(next);
      if (!safe?.startsWith("/oidc/authorize")) return null;
      return safe;
    } catch {
      return null;
    }
  }

  function openPopup(url) {
    const w = 600, h = 700;
    const y = (globalThis.top?.outerHeight || 800) / 2 + (globalThis.top?.screenY || 0) - h / 2;
    const x = (globalThis.top?.outerWidth || 1200) / 2 + (globalThis.top?.screenX || 0) - w / 2;
    return globalThis.open(
      url,
      "mediaAuth",
      `width=${w},height=${h},left=${x},top=${y},resizable=yes,scrollbars=yes`
    );
  }

  function replaceHomeTarget(target, continueTarget, needsMFA) {
    if (needsMFA || !continueTarget) return target;
    try {
      const parsed = new URL(target, globalThis.location.origin);
      return parsed.pathname === "/home" ? continueTarget : target;
    } catch {
      return target;
    }
  }

  function addContinueTargetToMFA(target, continueTarget) {
    if (!continueTarget) return target;
    try {
      const parsed = new URL(target, globalThis.location.origin);
      if (parsed.pathname !== "/mfa/challenge" || parsed.searchParams.has("next")) return target;
      parsed.searchParams.set("next", continueTarget);
      return parsed.pathname + parsed.search;
    } catch {
      return target;
    }
  }

  function finalizeNavigation(redirect, needsMFA) {
    const continueTarget = continueTargetFromLocation();
    let target = safeRedirect(redirect) || (needsMFA ? "/mfa/challenge" : "/home");
    target = replaceHomeTarget(target, continueTarget, needsMFA);
    target = addContinueTargetToMFA(target, continueTarget);

    sessionStorage.removeItem("authportal.oauth.next");
    lastAuthRedirect = target;
    globalThis.location.assign(target);
  }

  function notifyOpener(payload) {
    try {
      if (globalThis.opener && !globalThis.opener.closed) {
        globalThis.opener.postMessage(
          {
            ok: true,
            type: payload?.type || "auth-portal",
            redirect: payload?.redirect || "/home",
            mfa: !!payload?.mfa
          },
          globalThis.location.origin
        );
      }
    } catch (err) {
      console.warn("auth completion postMessage failed", err);
    }
  }

  function handlePopupCompletionIfNeeded() {
    const body = document.body;
    if (!body) return false;
    const data = body.dataset || {};
    if (data.authComplete !== "1") {
      return false;
    }
    if (!globalThis.opener || globalThis.opener.closed) {
      finalizeNavigation(data.authRedirect || "/home", data.authMfa === "true");
      return true;
    }
    notifyOpener({
      type: data.authProvider || "auth-portal",
      redirect: data.authRedirect || "/home",
      mfa: data.authMfa === "true"
    });
    setTimeout(() => {
      try {
        globalThis.close();
      } catch (err) {
        console.warn("window.close failed", err);
      }
    }, 600);
    return true;
  }

  if (handlePopupCompletionIfNeeded()) {
    return;
  }

  // Only accept messages from our own origin
  globalThis.addEventListener("message", (ev) => {
    if (ev.origin !== globalThis.location.origin) return;
    if (oauthCancelled) return;
    const d = ev.data || {};
    if (d?.ok && (d.type === "plex-auth" || d.type === "emby-auth" || d.type === "jellyfin-auth" || d.type === "auth-portal")) {
      finalizeNavigation(d.redirect, !!d.mfa);
    }
  });

  // --- Minimal addition: figure out current provider from the button ---
  function detectProvider(btn) {
    // 1) Prefer explicit data attribute if ever added
    const dp = (btn?.dataset?.provider || "").toLowerCase();
    if (dp) return dp;

    // 2) Infer from class name pattern "{{.ProviderKey}}-btn"
    const cl = new Set([...(btn?.classList || [])].map((c) => c.toLowerCase()));
    if (cl.has("plex-btn")) return "plex";
    if (cl.has("emby-btn")) return "emby";
    if (cl.has("jellyfin-btn")) return "jellyfin";

    // 3) Try the icon filename
    const img = btn?.querySelector("img");
    const src = (img?.getAttribute("src") || "").toLowerCase();
    if (src.includes("plex")) return "plex";
    if (src.includes("emby")) return "emby";
    if (src.includes("jellyfin")) return "jellyfin";

    // 4) Last resort: button text
    const txt = (btn?.textContent || "").toLowerCase();
    if (txt.includes("plex")) return "plex";
    if (txt.includes("emby")) return "emby";
    if (txt.includes("jellyfin")) return "jellyfin";

    return "plex"; // default
  }

  async function resolveAuthUrl(provider) {
    try {
      const res = await fetch("/auth/start-web", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Accept": "application/json" }
      });
      if (res.ok) {
        const j = await res.json().catch(() => ({}));
        const candidate = j.authUrl || j.url || j.location || null;
        if (candidate) {
          return candidate;
        }
      }
    } catch {}
    return provider === "jellyfin" ? "/auth/forward?jellyfin=1" : "/auth/forward?emby=1";
  }

  function preparePopup(popup) {
    try {
      const doc = popup?.document;
      if (!doc) return;
      doc.title = "Starting sign-in…";
      const body = doc.body || doc.createElement("body");
      body.style.fontFamily = "system-ui";
      body.style.padding = "1rem";
      body.textContent = "Starting sign-in…";
      if (!doc.body) doc.appendChild(body);
    } catch {}
  }

  function navigatePopup(popup, authUrl) {
    if (!popup || popup.closed) return false;
    try {
      popup.location.replace(authUrl);
    } catch {
      popup.location.href = authUrl;
    }
    return true;
  }

  function startPlexPolling(popup) {
    let pollTimer = null;
    let pollStopped = false;
    let pollInFlight = false;

    const stopPolling = () => {
      pollStopped = true;
      if (pollTimer) {
        clearTimeout(pollTimer);
        pollTimer = null;
      }
    };
    const schedulePoll = (delayMs) => {
      if (!pollStopped) pollTimer = setTimeout(runPollOnce, delayMs);
    };
    const runPollOnce = async () => {
      if (pollStopped || pollInFlight) {
        schedulePoll(2500);
        return;
      }
      pollInFlight = true;
      try {
        const response = await fetch("/auth/poll", {
          method: "GET",
          credentials: "same-origin",
          headers: { "Accept": "application/json" }
        });
        if (!response.ok) {
          schedulePoll(3000);
          return;
        }
        const result = await response.json().catch(() => ({}));
        if (pollStopped || oauthCancelled) return;
        if (result?.ok) {
          stopPolling();
          try { if (popup && !popup.closed) popup.close(); } catch {}
          finalizeNavigation(result.redirect, !!result.mfa);
          return;
        }
        schedulePoll(2500);
      } catch {
        schedulePoll(3000);
      } finally {
        pollInFlight = false;
      }
    };

    schedulePoll(2200);
    return stopPolling;
  }

  function monitorPopupClosure(popup, stopPolling) {
    const interval = setInterval(() => {
      if (popup && !popup.closed) return;
      clearInterval(interval);
      stopPolling();
      if (oauthCancelled) return;
      if (continueTargetFromLocation()) {
        const status = document.getElementById("auth-status");
        if (status) status.textContent = "Login window closed. Sign in again, or cancel and return to the application.";
        return;
      }
      globalThis.location.assign(lastAuthRedirect);
    }, 1200);
    return () => clearInterval(interval);
  }

  function showPopupError(popup) {
    try {
      if (popup && !popup.closed && popup.document) {
        popup.document.body.innerHTML =
          `<p style="font-family:system-ui;color:#b91c1c">Could not start login. Please try again.</p>`;
      }
    } catch {}
  }

  async function startFlow(btn) {
    if (oauthCancelled) return;
    const provider = detectProvider(btn); // "plex" | "emby" | "jellyfin"

    // Open placeholder popup synchronously (prevents popup blockers)
    const popup = openPopup("about:blank");
    preparePopup(popup);
    activeLoginCleanup = () => { try { if (popup && !popup.closed) popup.close(); } catch {} };

    btn.disabled = true;
    try {
      const authUrl = await resolveAuthUrl(provider);
      if (oauthCancelled) return;

      if (!navigatePopup(popup, authUrl)) {
        // Popup blocked → full-page navigation
        globalThis.location.assign(authUrl);
        return;
      }

      // Fallback for Plex: poll backend to finish PIN flow if Plex doesn't redirect to /auth/forward
      const stopPlexPolling = provider === "plex" ? startPlexPolling(popup) : () => {};

      // If user closes the popup, head to /home
      const stopClosureMonitor = monitorPopupClosure(popup, stopPlexPolling);
      activeLoginCleanup = () => {
        stopPlexPolling(); stopClosureMonitor();
        try { if (popup && !popup.closed) popup.close(); } catch {}
      };

    } catch (err) {
      if (oauthCancelled) return;
      console.error(err);
      showPopupError(popup);
      alert("Could not start login. Please try again.");
    } finally {
      btn.disabled = false;
    }
  }

  function bind() {
    const btn =
      document.getElementById("auth-signin") ||
      document.querySelector("[data-auth-signin]") ||
      document.querySelector(".auth-signin");
    if (!btn) return false;

    // If inside a form, prevent default submit
    const form = btn.closest("form");
    if (form) {
      form.addEventListener("submit", (e) => { e.preventDefault(); startFlow(btn); });
    }

    btn.addEventListener("click", (e) => { e.preventDefault(); startFlow(btn); });
    return true;
  }

  // Keep the requesting application flow on AuthPortal while Plex uses a popup.
  const oauthNext = new URLSearchParams(location.search).get("next");
  const safeNext = safeRedirect(oauthNext);
  if (safeNext && new URL(safeNext, location.origin).pathname === "/oidc/authorize") {
    const btn = document.getElementById("auth-signin");
    const cancel = document.getElementById("auth-cancel");
    const status = document.getElementById("auth-status");
    let starting = false;
    let popup = null;
    let stopPolling = () => {};
    let closureTimer = null;
    function cleanup() {
      stopPolling();
      if (closureTimer) clearInterval(closureTimer);
      closureTimer = null;
      try { if (popup && !popup.closed) popup.close(); } catch {}
    }
    const start = async () => {
      if (oauthCancelled || starting) return;
      // Must open synchronously, before fetching the PIN, for click-based retry.
      popup = openPopup("about:blank");
      if (!popup || popup.closed) {
        status.textContent = "Could not open the Plex login window. Allow popups for this site and try again.";
        btn.disabled = false;
        return;
      }
      preparePopup(popup);
      starting = true;
      btn.disabled = true;
      status.textContent = "Complete Plex sign-in in the popup, or cancel below.";
      try {
        const res = await fetch("/auth/start-web", {
          method: "POST", credentials: "same-origin", headers: { Accept: "application/json" }
        });
        if (!res.ok) throw new Error("Could not start Plex sign-in");
        const result = await res.json();
        const dest = new URL(result.url);
        if (dest.origin !== "https://app.plex.tv" || dest.pathname !== "/auth") throw new Error("Invalid Plex URL");
        if (oauthCancelled) return;
        sessionStorage.setItem("authportal.oauth.next", safeNext);
        if (!navigatePopup(popup, dest.href)) throw new Error("Popup closed");
        stopPolling = startPlexPolling(popup);
        closureTimer = setInterval(() => {
          if (popup && !popup.closed) return;
          cleanup();
          starting = false;
          btn.disabled = false;
          status.textContent = "Login window closed. Sign in again, or cancel and return to the application.";
        }, 1200);
      } catch {
        cleanup();
        if (oauthCancelled) return;
        status.textContent = "Could not start Plex sign-in. Please try again or cancel.";
        btn.disabled = false;
        starting = false;
      }
    };
    if (btn && cancel && status) {
      sessionStorage.setItem("authportal.oauth.next", safeNext);
      cancel.hidden = false;
      cancel.addEventListener("click", async () => {
        oauthCancelled = true;
        cleanup();
        activeLoginCleanup();
        btn.disabled = true;
        cancel.disabled = true;
        try {
          const res = await fetch("/oidc/login/cancel", {
            method: "POST", credentials: "same-origin",
            headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
            body: new URLSearchParams({ next: safeNext })
          });
          if (!res.ok) throw new Error("Cancellation failed");
          const result = await res.json();
          sessionStorage.removeItem("authportal.oauth.next");
          location.assign(result.redirect);
        } catch {
          status.textContent = "Could not return to the application. Please retry cancellation.";
          cancel.disabled = false;
        }
      });
    }
    if (btn && detectProvider(btn) === "plex") {
      btn.addEventListener("click", e => { e.preventDefault(); void start(); });
      globalThis.addEventListener("pagehide", cleanup);
      return;
    }
  }

  // Bind now; if not yet in DOM, bind on DOMContentLoaded; as a last resort, poll briefly
  if (!bind()) {
    document.addEventListener("DOMContentLoaded", bind);
    let tries = 0;
    const t = setInterval(() => { if (bind() || ++tries > 10) clearInterval(t); }, 150);
  }
})();
