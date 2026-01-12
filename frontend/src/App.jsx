const navItems = [
  { id: "providers", label: "Providers" },
  { id: "security", label: "Security" },
  { id: "mfa", label: "MFA" },
  { id: "app-settings", label: "App Settings" },
  { id: "users", label: "Users" },
  { id: "oauth", label: "OAuth Clients" },
  { id: "backups", label: "Backups" },
  { id: "audit", label: "Audit Logs" }
];

export default function App() {
  return (
    <>
      <header className="admin-header">
        <div>
          <h1>AuthPortal Admin Console</h1>
          <p className="muted">
            Active Provider: <span className="highlight">-</span> &bull; Last
            refreshed <span id="loaded-at">-</span>
          </p>
        </div>
        <a className="admin-home-link" href="/home">
          Back to Portal
        </a>
      </header>

      <div id="status-banner" className="status-banner"></div>

      <main className="admin-main">
        <aside className="admin-nav">
          {navItems.map((item, index) => (
            <button
              key={item.id}
              type="button"
              className={`admin-tab${index === 0 ? " active" : ""}`}
              data-section={item.id}
            >
              {item.label}
            </button>
          ))}
        </aside>

        <section className="admin-content">
          <div className="admin-panels">
            <div className="panel">
              <div className="panel-header">
                <h2>Providers</h2>
                <div className="panel-header-actions">
                  <button
                    type="button"
                    className="icon-btn"
                    aria-label="Show help for this configuration"
                    title="Show help"
                  >
                    ?
                  </button>
                  <span className="version-badge">v-</span>
                </div>
              </div>
              <p className="panel-helper">
                Phase 1 scaffold: layout only, no data wiring yet.
              </p>
              <div className="muted">Admin panel content will render here.</div>
            </div>

            <div className="panel history-panel">
              <h3>Recent Changes</h3>
              <ul className="history-list">
                <li>Waiting for activity.</li>
              </ul>
            </div>
          </div>
        </section>
      </main>

      <footer className="admin-footer">
        <p>Configuration updates apply immediately.</p>
      </footer>
    </>
  );
}
