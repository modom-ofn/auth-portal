(() => {
  const btn = document.getElementById("auth-signin");
  if (!btn) return;

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

  window.addEventListener("message", (ev) => {
    try {
      const d = ev.data || {};
      if (d && d.ok && (d.type === "plex-auth" || d.type === "emby-auth" || d.type === "auth-portal")) {
        window.location.assign(d.redirect || "/home");
      }
    } catch (_) {}
  });

  btn.addEventListener("click", async (e) => {
    e.preventDefault();
    btn.disabled = true;
    try {
      const res = await fetch("/auth/start-web", { method: "POST" });
      if (!res.ok) throw new Error(`start-web ${res.status}`);
      const j = await res.json();
      const authUrl = j.authUrl || j.url || j.location;
      if (!authUrl) throw new Error("no authUrl from server");
      const popup = openPopup(authUrl);
      const iv = setInterval(() => {
        if (!popup || popup.closed) {
          clearInterval(iv);
          window.location.assign("/home");
        }
      }, 1200);
    } catch (err) {
      console.error(err);
      alert("Could not start login. Please try again.");
    } finally {
      btn.disabled = false;
    }
  });
})();