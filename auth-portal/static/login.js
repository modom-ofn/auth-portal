// /static/login.js
(() => {
  let lastAuthRedirect = "/home";

  function openPopup(url) {
    const w = 600, h = 700;
    const y = (window.top?.outerHeight || 800) / 2 + (window.top?.screenY || 0) - h / 2;
    const x = (window.top?.outerWidth || 1200) / 2 + (window.top?.screenX || 0) - w / 2;
    return window.open(
      url,
      "mediaAuth",
      `width=${w},height=${h},left=${x},top=${y},resizable=yes,scrollbars=yes`
    );
  }

  function finalizeNavigation(redirect, needsMFA) {
    const target = redirect || (needsMFA ? "/mfa/challenge" : "/home");
    lastAuthRedirect = target;
    window.location.assign(target);
  }

  // Only accept messages from our own origin
  window.addEventListener("message", (ev) => {
    if (ev.origin !== window.location.origin) return;
    const d = ev.data || {};
    if (d && d.ok && (d.type === "plex-auth" || d.type === "emby-auth" || d.type === "jellyfin-auth" || d.type === "auth-portal")) {
      finalizeNavigation(d.redirect, !!d.mfa);
    }
  });

  // --- Minimal addition: figure out current provider from the button ---
  function detectProvider(btn) {
    // 1) Prefer explicit data attribute if ever added
    const dp = (btn?.getAttribute("data-provider") || "").toLowerCase();
    if (dp) return dp;

    // 2) Infer from class name pattern "{{.ProviderKey}}-btn"
    const cl = [...(btn?.classList || [])].map(c => c.toLowerCase());
    if (cl.includes("plex-btn")) return "plex";
    if (cl.includes("emby-btn")) return "emby";
    if (cl.includes("jellyfin-btn")) return "jellyfin";

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

  async function startFlow(btn) {
    const provider = detectProvider(btn); // "plex" | "emby" | "jellyfin"

    // Open placeholder popup synchronously (prevents popup blockers)
    let popup = openPopup("about:blank");
    try {
      if (popup?.document) {
        popup.document.write(`<!doctype html><meta charset="utf-8"><title>Starting sign-in…</title>
          <body style="font-family:system-ui;padding:1rem">Starting sign-in…</body>`);
        popup.document.close();
      }
    } catch {}

    btn.disabled = true;
    try {
      let authUrl = null;

      // Ask backend for the correct URL for the active provider
      try {
        const res = await fetch("/auth/start-web", {
          method: "POST",
          credentials: "same-origin",
          headers: { "Accept": "application/json" }
        });
        if (res.ok) {
          const j = await res.json().catch(() => ({}));
          authUrl = j.authUrl || j.url || j.location || null;
        }
      } catch {}
      // Fallbacks by provider if backend didn't return a URL
      if (!authUrl) {
        authUrl = provider === "jellyfin" ? "/auth/forward?jellyfin=1" : "/auth/forward?emby=1";
      }

      if (popup && !popup.closed) {
        try { popup.location.replace(authUrl); } catch { popup.location.href = authUrl; }
      } else {
        // Popup blocked → full-page navigation
        window.location.assign(authUrl);
        return;
      }

      // Fallback for Plex: poll backend to finish PIN flow if Plex doesn't redirect to /auth/forward
      let pollTimer = null;
      if (provider === "plex") {
        pollTimer = setInterval(async () => {
          try {
            const r = await fetch("/auth/poll", {
              method: "GET",
              credentials: "same-origin",
              headers: { "Accept": "application/json" }
            });
            if (!r.ok) return;
            const j = await r.json().catch(() => ({}));
            if (j && j.ok) {
              clearInterval(pollTimer);
              try { if (popup && !popup.closed) popup.close(); } catch {}
              finalizeNavigation(j.redirect, !!j.mfa);
            }
          } catch {}
        }, 1200);
      }

      // If user closes the popup, head to /home
      const iv = setInterval(() => {
        if (!popup || popup.closed) {
          clearInterval(iv);
          if (pollTimer) clearInterval(pollTimer);
          window.location.assign(lastAuthRedirect);
        }
      }, 1200);

    } catch (err) {
      console.error(err);
      try {
        if (popup && !popup.closed && popup.document) {
          popup.document.body.innerHTML =
            `<p style="font-family:system-ui;color:#b91c1c">Could not start login. Please try again.</p>`;
        }
      } catch {}
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

  // Bind now; if not yet in DOM, bind on DOMContentLoaded; as a last resort, poll briefly
  if (!bind()) {
    document.addEventListener("DOMContentLoaded", bind);
    let tries = 0;
    const t = setInterval(() => { if (bind() || ++tries > 10) clearInterval(t); }, 150);
  }
})();
