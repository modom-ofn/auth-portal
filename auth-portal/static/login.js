// /static/login.js
(() => {
  const SELECTORS = [
    "#auth-signin",
    "[data-auth-signin]",
    ".auth-signin",
    'button[name="auth-signin"]',
    'a[href="#auth-signin"]'
  ];

  function findButton() {
    for (const sel of SELECTORS) {
      const el = document.querySelector(sel);
      if (el) return el;
    }
    return null;
  }

  function openPopup(url) {
    const w = 600, h = 700;
    const y = window.top.outerHeight / 2 + window.top.screenY - (h / 2);
    const x = window.top.outerWidth / 2 + window.top.screenX - (w / 2);
    return window.open(
      url,
      "mediaAuth",
      `width=${w},height=${h},left=${x},top=${y},resizable=yes,scrollbars=yes`
    );
  }

  // Only accept postMessages from same origin
  window.addEventListener("message", (ev) => {
    if (ev.origin !== window.location.origin) return;
    const d = ev.data || {};
    if (d && d.ok && (d.type === "plex-auth" || d.type === "emby-auth" || d.type === "auth-portal")) {
      window.location.assign(d.redirect || "/home");
    }
  });

  async function startFlow(btn) {
    // Open popup synchronously to keep user gesture
    let popup = openPopup("about:blank");

    // Paint a tiny waiting page (optional)
    try {
      if (popup && popup.document) {
        popup.document.write(
          `<!doctype html><meta charset="utf-8"><title>Starting sign-in…</title>
           <body style="font-family:system-ui;line-height:1.4;padding:1rem">
             <p>Starting sign-in…</p>
           </body>`
        );
        popup.document.close();
      }
    } catch {}

    btn.disabled = true;
    try {
      const res = await fetch("/auth/start-web", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Accept": "application/json" }
      });
      if (!res.ok) throw new Error(`start-web ${res.status}`);
      const j = await res.json();
      const authUrl = j.authUrl || j.url || j.location;
      if (!authUrl) throw new Error("no authUrl from server");

      if (popup && !popup.closed) {
        try { popup.location.replace(authUrl); } catch { popup.location.href = authUrl; }
      } else {
        // Popup blocked → degrade to full page
        window.location.assign(authUrl);
        return;
      }

      // If user closes popup, go to /home as a fallback
      const iv = setInterval(() => {
        if (!popup || popup.closed) {
          clearInterval(iv);
          window.location.assign("/home");
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
    const btn = findButton();
    if (!btn) return false;

    // If the button is inside a form, prevent the form submit
    const form = btn.closest("form");
    if (form) {
      form.addEventListener("submit", (e) => {
        e.preventDefault();
        startFlow(btn);
      });
    }

    // Click handler (covers non-form buttons/links)
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      startFlow(btn);
    });

    return true;
  }

  // Try immediately…
  if (!bind()) {
    // …then on DOM ready…
    document.addEventListener("DOMContentLoaded", bind);
    // …and as a last resort, poll briefly for dynamically-rendered buttons.
    let tries = 0;
    const t = setInterval(() => {
      if (bind() || ++tries > 10) clearInterval(t);
    }, 150);
  }
})();