import { useState, useEffect, useRef } from "react";

const COLORS = {
  bg: "#080c14",
  bgPanel: "rgba(12, 18, 30, 0.85)",
  bgCard: "rgba(16, 24, 40, 0.9)",
  border: "rgba(0, 200, 255, 0.12)",
  borderBright: "rgba(0, 200, 255, 0.35)",
  cyan: "#00c8ff",
  cyanDim: "rgba(0,200,255,0.15)",
  cyanGlow: "rgba(0,200,255,0.4)",
  green: "#00ff9d",
  greenDim: "rgba(0,255,157,0.15)",
  amber: "#ffb300",
  amberDim: "rgba(255,179,0,0.15)",
  red: "#ff3d5a",
  redDim: "rgba(255,61,90,0.15)",
  textPrimary: "#e8f4ff",
  textSecondary: "#7a9bb5",
  textMuted: "#3d5870",
};

const css = `
  @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=Space+Mono:wght@400;700&display=swap');
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: ${COLORS.bg}; color: ${COLORS.textPrimary}; font-family: 'Space Grotesk', sans-serif; overflow: hidden; }
  ::-webkit-scrollbar { width: 4px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: ${COLORS.border}; border-radius: 2px; }
  .mono { font-family: 'Space Mono', monospace; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
  @keyframes scanline { 0%{transform:translateY(-100%)} 100%{transform:translateY(100vh)} }
  @keyframes flicker { 0%,100%{opacity:1} 92%{opacity:0.97} 94%{opacity:0.85} 96%{opacity:0.95} }
  @keyframes countUp { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }
  @keyframes radarSpin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
  @keyframes floatIn { from{opacity:0;transform:translateX(20px)} to{opacity:1;transform:translateX(0)} }
  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
  @keyframes threatSlide { from{opacity:0;transform:translateX(-10px)} to{opacity:1;transform:translateX(0)} }
  @keyframes modalIn { from{opacity:0;transform:scale(0.95)} to{opacity:1;transform:scale(1)} }
  @keyframes warningPulse { 0%,100%{box-shadow:0 0 20px rgba(255,61,90,0.3)} 50%{box-shadow:0 0 60px rgba(255,61,90,0.8)} }
  @keyframes gridMove { 0%{background-position:0 0} 100%{background-position:40px 40px} }
`;

const glassMorphStyle = {
  background: COLORS.bgCard,
  border: `1px solid ${COLORS.border}`,
  borderRadius: 12,
  backdropFilter: "blur(12px)",
};

const sectionHead = (title, subtitle, color = COLORS.cyan) => (
  <div style={{ marginBottom: 16 }}>
    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
      <div style={{ width: 3, height: 16, background: color, borderRadius: 2 }} />
      <span style={{ fontSize: 11, fontFamily: "'Space Mono', monospace", color: COLORS.textSecondary, letterSpacing: "0.12em", textTransform: "uppercase" }}>{title}</span>
    </div>
    {subtitle && <div style={{ fontSize: 18, fontWeight: 600, color: COLORS.textPrimary, paddingLeft: 11 }}>{subtitle}</div>}
  </div>
);

function AnimCounter({ target, duration = 1200 }) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    const start = Date.now();
    const tick = () => {
      const p = Math.min((Date.now() - start) / duration, 1);
      setVal(Math.floor(p * target));
      if (p < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }, [target]);
  return <span>{val}</span>;
}

function StatusDot({ status }) {
  const colors = { safe: COLORS.green, monitoring: COLORS.cyan, warning: COLORS.amber, danger: COLORS.red };
  const c = colors[status] || COLORS.cyan;
  return (
    <span style={{ display: "inline-block", width: 8, height: 8, borderRadius: "50%", background: c, boxShadow: `0 0 6px ${c}`, animation: "pulse 2s infinite" }} />
  );
}

const navItems = [
  { id: "dashboard", label: "Dashboard", icon: "⬡" },
  { id: "timeline", label: "Threat Timeline", icon: "⏱" },
  { id: "email", label: "Email Security", icon: "✉" },
  { id: "websites", label: "Website Protection", icon: "🛡" },
  { id: "investigations", label: "Investigations", icon: "🔍" },
  { id: "factcheck", label: "Fact Checker", icon: "✓" },
  { id: "reports", label: "Reports", icon: "⎘" },
  { id: "settings", label: "Settings", icon: "⚙" },
];

const radarAngles = [90, 162, 234, 306, 18];

async function saturdayApi(path, payload = null) {
  const options = payload
    ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }
    : {};
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.message || "Saturday request failed");
  return data;
}

function incidentTarget(incident) {
  return incident.sender || incident.url || incident.target || "Unknown target";
}

function incidentStatus(incident) {
  const raw = String(incident.status || "pending").replaceAll("_", " ");
  return raw.charAt(0).toUpperCase() + raw.slice(1);
}

function incidentSource(incident) {
  if (incident.hackarena) return "HackArena";
  if (incident.source === "imap") return "IMAP";
  if (incident.source === "extension") return "Extension";
  if (incident.source === "dashboard") return "Dashboard";
  return incident.source || "Local";
}

function mapThreats(incidents) {
  return incidents.map(incident => ({
    id: incident.id,
    time: incident.time_label || "--:--",
    type: incident.title || (incident.kind === "email" ? "Suspicious Email" : "Security Event"),
    category: `${incidentSource(incident)} / ${incident.kind || "event"}`,
    risk: Number(incident.risk_score || 0),
    status: incidentStatus(incident),
    detail: `${incidentTarget(incident)}\n${(incident.reasons || []).join("\n")}`,
  }));
}

function mapEmails(incidents) {
  return incidents.filter(incident => incident.kind === "email").map(incident => ({
    id: incident.id,
    from: incident.sender || "Unknown sender",
    subject: incident.subject || incident.title || "(no subject)",
    risk: Number(incident.risk_score || 0),
    reasons: incident.reasons || [],
    status: incidentStatus(incident),
    time: incident.time_label || "--:--",
    source: incidentSource(incident),
    snippet: incident.snippet || "",
  }));
}

function mapWebsites(incidents) {
  return incidents.filter(incident => incident.kind === "web").map(incident => ({
    id: incident.id,
    url: incident.url || incident.target || "Unknown route",
    risk: Number(incident.risk_score || 0),
    reputation: incident.hackarena ? "HackArena match" : Number(incident.risk_score || 0) >= 70 ? "Blocked" : "Suspicious",
    reason: (incident.reasons || [incidentTarget(incident)])[0],
    action: incidentStatus(incident),
    source: incidentSource(incident),
  }));
}

function mapRadarData(incidents) {
  const buckets = [
    { label: "Email", value: incidents.filter(item => item.kind === "email").length },
    { label: "Web", value: incidents.filter(item => item.kind === "web").length },
    { label: "High Risk", value: incidents.filter(item => Number(item.risk_score || 0) >= 70).length },
    { label: "Contained", value: incidents.filter(item => String(item.status || "").includes("quarantined") || String(item.status || "").includes("blocked")).length },
    { label: "HackArena", value: incidents.filter(item => item.hackarena).length },
  ];
  const max = Math.max(1, ...buckets.map(item => item.value));
  return buckets.map((item, index) => ({
    ...item,
    value: Math.round((item.value / max) * 100),
    count: item.value,
    angle: radarAngles[index],
  }));
}

function getRiskColor(score) {
  if (score >= 80) return COLORS.red;
  if (score >= 60) return COLORS.amber;
  if (score >= 40) return COLORS.cyan;
  return COLORS.green;
}

function RiskBadge({ score, size = "sm" }) {
  const c = getRiskColor(score);
  const fs = size === "lg" ? 14 : 11;
  return (
    <span className="mono" style={{ background: `${c}20`, border: `1px solid ${c}50`, color: c, fontSize: fs, padding: "2px 8px", borderRadius: 4, fontWeight: 700, letterSpacing: "0.05em" }}>
      {score}
    </span>
  );
}

function StatusBadge({ status }) {
  const map = {
    Blocked: { bg: `${COLORS.red}20`, border: `${COLORS.red}50`, color: COLORS.red },
    blocked: { bg: `${COLORS.red}20`, border: `${COLORS.red}50`, color: COLORS.red },
    Quarantined: { bg: `${COLORS.amber}20`, border: `${COLORS.amber}50`, color: COLORS.amber },
    quarantined: { bg: `${COLORS.amber}20`, border: `${COLORS.amber}50`, color: COLORS.amber },
    Flagged: { bg: `${COLORS.cyan}20`, border: `${COLORS.cyan}50`, color: COLORS.cyan },
    flagged: { bg: `${COLORS.cyan}20`, border: `${COLORS.cyan}50`, color: COLORS.cyan },
    monitoring: { bg: `${COLORS.green}20`, border: `${COLORS.green}50`, color: COLORS.green },
    Warning: { bg: `${COLORS.amber}20`, border: `${COLORS.amber}50`, color: COLORS.amber },
    Safe: { bg: `${COLORS.green}20`, border: `${COLORS.green}50`, color: COLORS.green },
  };
  const s = map[status] || map.monitoring;
  return (
    <span style={{ background: s.bg, border: `1px solid ${s.border}`, color: s.color, fontSize: 10, padding: "2px 8px", borderRadius: 4, fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase" }}>
      {status}
    </span>
  );
}

function Sidebar({ activeNav, setActiveNav, sidebarOpen }) {
  return (
    <div style={{
      width: sidebarOpen ? 220 : 60,
      background: "rgba(6, 11, 22, 0.97)",
      borderRight: `1px solid ${COLORS.border}`,
      display: "flex",
      flexDirection: "column",
      padding: "20px 0",
      transition: "width 0.3s ease",
      overflow: "hidden",
      flexShrink: 0,
      position: "relative",
      zIndex: 10,
    }}>
      {/* Logo */}
      <div style={{ padding: "0 16px 28px", borderBottom: `1px solid ${COLORS.border}`, marginBottom: 16 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{
            width: 32, height: 32, borderRadius: 8,
            background: `linear-gradient(135deg, ${COLORS.cyan}30, ${COLORS.cyan}60)`,
            border: `1px solid ${COLORS.cyanGlow}`,
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 14, fontWeight: 700, color: COLORS.cyan,
            flexShrink: 0,
          }}>S</div>
          {sidebarOpen && (
            <div>
              <div style={{ fontSize: 14, fontWeight: 700, color: COLORS.textPrimary, letterSpacing: "0.05em" }}>SATURDAY</div>
              <div style={{ fontSize: 9, color: COLORS.textMuted, letterSpacing: "0.15em", textTransform: "uppercase" }}>AI Security</div>
            </div>
          )}
        </div>
        {sidebarOpen && (
          <div style={{ marginTop: 12, display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", background: `${COLORS.green}15`, borderRadius: 6, border: `1px solid ${COLORS.green}30` }}>
            <StatusDot status="safe" />
            <span style={{ fontSize: 11, color: COLORS.green, fontWeight: 600 }}>System Secure</span>
          </div>
        )}
      </div>

      {/* Nav items */}
      <div style={{ flex: 1, padding: "0 8px", overflowY: "auto" }}>
        {navItems.map(item => (
          <button
            key={item.id}
            onClick={() => setActiveNav(item.id)}
            style={{
              width: "100%",
              display: "flex",
              alignItems: "center",
              gap: 10,
              padding: sidebarOpen ? "9px 12px" : "9px",
              justifyContent: sidebarOpen ? "flex-start" : "center",
              borderRadius: 8,
              border: "none",
              background: activeNav === item.id ? `${COLORS.cyan}15` : "transparent",
              color: activeNav === item.id ? COLORS.cyan : COLORS.textSecondary,
              cursor: "pointer",
              marginBottom: 2,
              transition: "all 0.2s",
              borderLeft: activeNav === item.id ? `2px solid ${COLORS.cyan}` : "2px solid transparent",
            }}
          >
            <span style={{ fontSize: 14, flexShrink: 0 }}>{item.icon}</span>
            {sidebarOpen && <span style={{ fontSize: 13, fontWeight: activeNav === item.id ? 600 : 400 }}>{item.label}</span>}
          </button>
        ))}
      </div>

      {/* Bottom status */}
      {sidebarOpen && (
        <div style={{ padding: "16px", borderTop: `1px solid ${COLORS.border}`, marginTop: 8 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
            <div style={{ width: 6, height: 6, borderRadius: "50%", background: COLORS.cyan, animation: "pulse 2s infinite" }} />
            <span style={{ fontSize: 11, color: COLORS.textSecondary }}>AI Status: <span style={{ color: COLORS.cyan, fontWeight: 600 }}>Online</span></span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ width: 6, height: 6, borderRadius: "50%", background: COLORS.green, animation: "pulse 1.5s infinite" }} />
            <span style={{ fontSize: 11, color: COLORS.textSecondary }}>Monitor: <span style={{ color: COLORS.green, fontWeight: 600 }}>Active</span></span>
          </div>
        </div>
      )}
    </div>
  );
}

function Header({ sidebarOpen, setSidebarOpen, setShowThreatModal, incidents = [], aiEnabled = false }) {
  const now = new Date();
  const hour = now.getHours();
  const greeting = hour < 12 ? "Good Morning" : hour < 18 ? "Good Afternoon" : "Good Evening";
  const [notifOpen, setNotifOpen] = useState(false);
  const highRiskCount = incidents.filter(item => Number(item.risk_score || 0) >= 70).length;
  const notifications = mapThreats(incidents).slice(0, 3);
  const secureLabel = highRiskCount ? "ALERT" : "SECURE";
  const secureColor = highRiskCount ? COLORS.red : COLORS.green;

  return (
    <div style={{
      background: "rgba(6, 11, 22, 0.95)",
      borderBottom: `1px solid ${COLORS.border}`,
      padding: "14px 24px",
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      backdropFilter: "blur(10px)",
      flexShrink: 0,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
        <button onClick={() => setSidebarOpen(!sidebarOpen)} style={{ background: "none", border: "none", color: COLORS.textSecondary, cursor: "pointer", fontSize: 18, padding: 4 }}>
          ☰
        </button>
        <div>
          <div style={{ fontSize: 20, fontWeight: 700, color: COLORS.textPrimary }}>{greeting}.</div>
          <div style={{ fontSize: 12, color: COLORS.textSecondary, marginTop: 1 }}>{incidents.length} live security event{incidents.length === 1 ? "" : "s"} loaded from Saturday.</div>
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
        {/* Security level */}
        <div style={{
          padding: "6px 14px",
          background: `${secureColor}15`,
          border: `1px solid ${secureColor}40`,
          borderRadius: 20,
          display: "flex", alignItems: "center", gap: 8,
          cursor: "pointer",
        }}>
          <StatusDot status={highRiskCount ? "danger" : "safe"} />
          <span className="mono" style={{ fontSize: 12, color: secureColor, fontWeight: 700, letterSpacing: "0.1em" }}>{secureLabel}</span>
        </div>

        {/* Threat demo button */}
        <button
          onClick={() => setShowThreatModal(true)}
          style={{
            padding: "6px 12px",
            background: `${COLORS.red}15`,
            border: `1px solid ${COLORS.red}40`,
            borderRadius: 8,
            color: COLORS.red,
            fontSize: 11,
            cursor: "pointer",
            fontFamily: "'Space Mono', monospace",
            letterSpacing: "0.05em",
          }}>
          ⚡ Inspect Alert
        </button>

        {/* Notif bell */}
        <div style={{ position: "relative" }}>
          <button
            onClick={() => setNotifOpen(!notifOpen)}
            style={{ background: `${COLORS.border}`, border: `1px solid ${COLORS.border}`, borderRadius: 8, width: 36, height: 36, cursor: "pointer", color: COLORS.textSecondary, fontSize: 16 }}>
            🔔
          </button>
          <div style={{ position: "absolute", top: 6, right: 6, width: 8, height: 8, background: COLORS.red, borderRadius: "50%", border: "2px solid #080c14" }} />
          {notifOpen && (
            <div style={{
              position: "absolute", top: 44, right: 0, width: 280, zIndex: 100,
              background: "rgba(10, 16, 28, 0.98)", border: `1px solid ${COLORS.border}`,
              borderRadius: 10, padding: 12, boxShadow: `0 20px 60px rgba(0,0,0,0.6)`,
            }}>
              {(notifications.length ? notifications : [{ type: "No live incidents", category: aiEnabled ? "OpenRouter enabled" : "Local mode" }]).map((n, i) => (
                <div key={i} style={{ padding: "8px 10px", borderBottom: i < 2 ? `1px solid ${COLORS.border}` : "none", fontSize: 12, color: COLORS.textSecondary, display: "flex", gap: 8, alignItems: "flex-start" }}>
                  <span style={{ color: COLORS.cyan, marginTop: 1 }}>›</span>{n.type} — {n.category}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Profile */}
        <div style={{ width: 36, height: 36, borderRadius: 8, background: `linear-gradient(135deg, ${COLORS.cyan}30, #7b2dff30)`, border: `1px solid ${COLORS.cyan}40`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 13, fontWeight: 700, color: COLORS.cyan, cursor: "pointer" }}>
          AK
        </div>
      </div>
    </div>
  );
}

function HeroCard({ incidents = [] }) {
  const highRiskCount = incidents.filter(item => Number(item.risk_score || 0) >= 70).length;
  const blockedCount = incidents.filter(item => {
    const status = String(item.status || "").toLowerCase();
    return status.includes("quarantined") || status.includes("blocked") || (item.kind === "web" && Number(item.risk_score || 0) >= 70);
  }).length;
  const stats = [
    { label: "Threats Detected", value: incidents.filter(item => Number(item.risk_score || 0) >= 40).length, color: COLORS.red },
    { label: "Threats Blocked", value: blockedCount, color: COLORS.amber },
    { label: "Email Signals", value: incidents.filter(item => item.kind === "email").length, color: COLORS.cyan },
    { label: "HackArena Hits", value: incidents.filter(item => item.hackarena).length, color: COLORS.green },
  ];

  return (
    <div style={{
      ...glassMorphStyle,
      padding: 24,
      position: "relative",
      overflow: "hidden",
      background: "rgba(0,200,255,0.03)",
      border: `1px solid ${COLORS.cyanGlow}`,
    }}>
      {/* Background grid */}
      <div style={{
        position: "absolute", inset: 0,
        backgroundImage: `linear-gradient(${COLORS.border} 1px, transparent 1px), linear-gradient(90deg, ${COLORS.border} 1px, transparent 1px)`,
        backgroundSize: "40px 40px",
        opacity: 0.4,
      }} />

      <div style={{ position: "relative" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 24 }}>
          <div>
            <div className="mono" style={{ fontSize: 10, color: COLORS.textMuted, letterSpacing: "0.2em", marginBottom: 8 }}>SECURITY STATUS</div>
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <div style={{
                fontSize: 36, fontWeight: 700,
                background: `linear-gradient(135deg, ${COLORS.green}, ${COLORS.cyan})`,
                WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
                letterSpacing: "0.08em",
              }}>
                {highRiskCount ? "ALERT" : incidents.length ? "SAFE" : "READY"}
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                <StatusDot status="safe" />
                <div style={{ width: 2, height: 20, background: `${COLORS.green}40`, borderRadius: 1 }} />
              </div>
            </div>
            <div style={{ fontSize: 12, color: COLORS.textSecondary, marginTop: 4 }}>
              {highRiskCount ? `${highRiskCount} high-risk event${highRiskCount === 1 ? "" : "s"} need review` : `${incidents.length} event${incidents.length === 1 ? "" : "s"} in local memory`}
            </div>
          </div>

          {/* Pulse ring */}
          <div style={{ position: "relative", width: 80, height: 80 }}>
            <div style={{ position: "absolute", inset: 0, border: `1px solid ${COLORS.green}40`, borderRadius: "50%", animation: "pulse 2s infinite" }} />
            <div style={{ position: "absolute", inset: 10, border: `1px solid ${COLORS.green}60`, borderRadius: "50%", animation: "pulse 2s infinite 0.3s" }} />
            <div style={{ position: "absolute", inset: 20, background: `${COLORS.green}20`, border: `1px solid ${COLORS.green}`, borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <span style={{ fontSize: 22 }}>🛡</span>
            </div>
          </div>
        </div>

        {/* Stats row */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12 }}>
          {stats.map((s, i) => (
            <div key={i} style={{ background: "rgba(0,0,0,0.3)", border: `1px solid ${s.color}25`, borderRadius: 10, padding: 14 }}>
              <div style={{ fontSize: 28, fontWeight: 700, color: s.color, fontFamily: "'Space Mono', monospace", animation: "countUp 0.5s ease forwards" }}>
                <AnimCounter target={s.value} duration={1000 + i * 200} />
              </div>
              <div style={{ fontSize: 11, color: COLORS.textSecondary, marginTop: 2 }}>{s.label}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function AIBriefing({ briefing }) {
  const [typing, setTyping] = useState(false);
  const [text, setText] = useState("");
  const fullText = briefing || "Saturday is connected. Run an IMAP scan or let the browser guard add a route verdict.";

  useEffect(() => {
    let i = 0;
    setTyping(true);
    const t = setInterval(() => {
      setText(fullText.slice(0, i));
      i += 2;
      if (i > fullText.length) { setTyping(false); clearInterval(t); }
    }, 30);
    return () => clearInterval(t);
  }, [fullText]);

  return (
    <div style={{ ...glassMorphStyle, padding: 20, background: "rgba(0,200,255,0.02)" }}>
      {sectionHead("AI BRIEFING", null, COLORS.cyan)}
      <div style={{
        background: "rgba(0,0,0,0.4)",
        border: `1px solid ${COLORS.border}`,
        borderRadius: 8,
        padding: 16,
        fontFamily: "'Space Mono', monospace",
        fontSize: 12,
        color: COLORS.textSecondary,
        lineHeight: 1.8,
        minHeight: 160,
        position: "relative",
        whiteSpace: "pre-wrap",
      }}>
        <div style={{ position: "absolute", top: 10, right: 12, display: "flex", gap: 6 }}>
          <div style={{ fontSize: 9, color: COLORS.cyan, letterSpacing: "0.1em" }}>SATURDAY AI</div>
          <div style={{ width: 6, height: 6, background: COLORS.cyan, borderRadius: "50%", animation: "pulse 1.5s infinite", marginTop: 1 }} />
        </div>
        <span style={{ color: COLORS.textPrimary }}>{text}</span>
        {typing && <span style={{ animation: "blink 1s infinite", color: COLORS.cyan }}>█</span>}
      </div>
    </div>
  );
}

function ThreatTimeline({ threats = [] }) {
  const [expanded, setExpanded] = useState(null);

  return (
    <div style={{ ...glassMorphStyle, padding: 20 }}>
      {sectionHead("THREAT TIMELINE", "Today's Incidents", COLORS.red)}
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {threats.length === 0 && (
          <div style={{ color: COLORS.textSecondary, fontSize: 12, padding: 16, border: `1px solid ${COLORS.border}`, borderRadius: 8 }}>
            No live incidents yet.
          </div>
        )}
        {threats.map((t, i) => (
          <div
            key={i}
            onClick={() => setExpanded(expanded === i ? null : i)}
            style={{
              background: "rgba(0,0,0,0.3)",
              border: `1px solid ${expanded === i ? getRiskColor(t.risk) + "50" : COLORS.border}`,
              borderRadius: 8,
              padding: "10px 14px",
              cursor: "pointer",
              transition: "all 0.2s",
              animation: `threatSlide ${0.1 + i * 0.08}s ease forwards`,
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <div className="mono" style={{ fontSize: 10, color: COLORS.textMuted, minWidth: 60 }}>{t.time}</div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 13, fontWeight: 600, color: COLORS.textPrimary }}>{t.type}</div>
                <div style={{ fontSize: 11, color: COLORS.textSecondary }}>{t.category}</div>
              </div>
              <RiskBadge score={t.risk} />
              <StatusBadge status={t.status} />
              <div style={{ color: COLORS.textMuted, fontSize: 12 }}>{expanded === i ? "▲" : "▼"}</div>
            </div>
            {expanded === i && (
              <div style={{ marginTop: 10, paddingTop: 10, borderTop: `1px solid ${COLORS.border}`, fontSize: 12, color: COLORS.textSecondary, lineHeight: 1.6 }}>
                {t.detail}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function EmailPanel({ emails = [], setEmailDetail, onAction }) {
  return (
    <div style={{ ...glassMorphStyle, padding: 20 }}>
      {sectionHead("EMAIL SECURITY", "Suspicious Emails", COLORS.amber)}
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {emails.length === 0 && (
          <div style={{ color: COLORS.textSecondary, fontSize: 12, padding: 16, border: `1px solid ${COLORS.border}`, borderRadius: 8 }}>
            No live email incidents yet.
          </div>
        )}
        {emails.map((e, i) => (
          <div key={i} style={{
            background: "rgba(0,0,0,0.3)",
            border: `1px solid ${COLORS.border}`,
            borderRadius: 8,
            padding: 14,
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 8 }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 12, color: COLORS.textMuted, fontFamily: "'Space Mono', monospace", marginBottom: 2, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.from}</div>
                <div style={{ fontSize: 13, fontWeight: 600, color: COLORS.textPrimary }}>{e.subject}</div>
              </div>
              <div style={{ display: "flex", gap: 8, flexShrink: 0, marginLeft: 12 }}>
                <RiskBadge score={e.risk} />
                <StatusBadge status={e.status} />
              </div>
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 10 }}>
              {e.reasons.map((r, j) => (
                <span key={j} style={{ fontSize: 10, background: `${COLORS.amber}15`, border: `1px solid ${COLORS.amber}30`, color: COLORS.amber, padding: "2px 8px", borderRadius: 4 }}>{r}</span>
              ))}
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <button onClick={() => setEmailDetail(e)} style={{ fontSize: 11, padding: "4px 12px", background: `${COLORS.cyan}20`, border: `1px solid ${COLORS.cyan}50`, color: COLORS.cyan, borderRadius: 6, cursor: "pointer" }}>Explain</button>
              <button onClick={() => onAction?.("ARCHIVE_EMAIL", e.id)} style={{ fontSize: 11, padding: "4px 12px", background: "transparent", border: `1px solid ${COLORS.border}`, color: COLORS.textSecondary, borderRadius: 6, cursor: "pointer" }}>Archive</button>
              <button onClick={() => onAction?.("BLOCK_SENDER", e.id)} style={{ fontSize: 11, padding: "4px 12px", background: "transparent", border: `1px solid ${COLORS.border}`, color: COLORS.textSecondary, borderRadius: 6, cursor: "pointer" }}>Block</button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function WebsitePanel({ websites = [] }) {
  return (
    <div style={{ ...glassMorphStyle, padding: 20 }}>
      {sectionHead("WEBSITE PROTECTION", "Analyzed Domains", COLORS.cyan)}
      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
          <thead>
            <tr style={{ borderBottom: `1px solid ${COLORS.border}` }}>
              {["URL", "Risk", "Reputation", "Reason", "Action"].map(h => (
                <th key={h} style={{ textAlign: "left", padding: "8px 10px", color: COLORS.textMuted, fontSize: 10, letterSpacing: "0.1em", fontWeight: 600, textTransform: "uppercase", whiteSpace: "nowrap" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {websites.length === 0 && (
              <tr>
                <td colSpan="5" style={{ padding: 16, color: COLORS.textSecondary }}>No live website incidents yet.</td>
              </tr>
            )}
            {websites.map((w, i) => (
              <tr key={i} style={{ borderBottom: `1px solid ${COLORS.border}30` }}>
                <td style={{ padding: "10px", fontFamily: "'Space Mono', monospace", color: COLORS.red, fontSize: 11 }}>{w.url}</td>
                <td style={{ padding: "10px" }}><RiskBadge score={w.risk} /></td>
                <td style={{ padding: "10px", color: getRiskColor(w.risk), fontSize: 11 }}>{w.reputation}</td>
                <td style={{ padding: "10px", color: COLORS.textSecondary }}>{w.reason}</td>
                <td style={{ padding: "10px" }}><StatusBadge status={w.action} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function RadarChart({ radarData = [] }) {
  const cx = 120, cy = 120, r = 80;
  const levels = [20, 40, 60, 80, 100];
  const data = radarData.length ? radarData : mapRadarData([]);

  const pt = (angle, val) => {
    const a = (angle - 90) * Math.PI / 180;
    const rad = (val / 100) * r;
    return { x: cx + rad * Math.cos(a), y: cy + rad * Math.sin(a) };
  };

  const polygon = data.map(d => pt(d.angle, d.value));
  const polyStr = polygon.map(p => `${p.x},${p.y}`).join(" ");

  return (
    <div style={{ ...glassMorphStyle, padding: 20, textAlign: "center" }}>
      {sectionHead("THREAT RADAR", "Live Risk Levels", COLORS.red)}
      <svg width="240" height="240" viewBox="0 0 240 240" style={{ overflow: "visible" }}>
        {/* Grid rings */}
        {levels.map(lv => (
          <polygon key={lv} points={data.map(d => { const p = pt(d.angle, lv); return `${p.x},${p.y}`; }).join(" ")}
            fill="none" stroke={COLORS.border} strokeWidth="0.5" />
        ))}
        {/* Spokes */}
        {data.map((d, i) => {
          const p = pt(d.angle, 100);
          return <line key={i} x1={cx} y1={cy} x2={p.x} y2={p.y} stroke={COLORS.border} strokeWidth="0.5" />;
        })}
        {/* Spinning sweep */}
        <g style={{ transformOrigin: `${cx}px ${cy}px`, animation: "radarSpin 4s linear infinite" }}>
          <path d={`M ${cx} ${cy} L ${cx} ${cy - r} A ${r} ${r} 0 0 1 ${cx + r * Math.sin(60 * Math.PI / 180)} ${cy - r * Math.cos(60 * Math.PI / 180)} Z`}
            fill={`${COLORS.green}15`} />
        </g>
        {/* Data polygon */}
        <polygon points={polyStr} fill={`${COLORS.cyan}15`} stroke={COLORS.cyan} strokeWidth="1.5" />
        {data.map((d, i) => {
          const p = pt(d.angle, d.value);
          return <circle key={i} cx={p.x} cy={p.y} r="4" fill={getRiskColor(d.value)} style={{ animation: "pulse 2s infinite" }} />;
        })}
        {/* Labels */}
        {data.map((d, i) => {
          const lp = pt(d.angle, 115);
          return (
            <text key={i} x={lp.x} y={lp.y} fill={COLORS.textSecondary} fontSize="10" textAnchor="middle" dominantBaseline="central">
              {d.label}
            </text>
          );
        })}
        {/* Center */}
        <circle cx={cx} cy={cy} r="4" fill={COLORS.cyan} />
      </svg>
    </div>
  );
}

function FactChecker() {
  const [query, setQuery] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const check = async () => {
    if (!query.trim()) return;
    setLoading(true);
    setResult(null);
    try {
      const data = await saturdayApi("/api/command", { message: `Fact check: ${query}` });
      setResult({
        verdict: data.ok ? "ANSWER" : "UNAVAILABLE",
        confidence: data.ok ? 100 : 0,
        explanation: data.message || "Saturday could not answer this claim.",
        evidence: [],
        sourceReliability: data.ok ? "Local Saturday backend" : "Uncertain",
      });
    } catch (e) {
      setResult({ verdict: "ERROR", confidence: 0, explanation: "Unable to verify at this time.", evidence: [], sourceReliability: "Uncertain" });
    }
    setLoading(false);
  };

  const verdictColors = { ANSWER: COLORS.green, UNAVAILABLE: COLORS.amber, ERROR: COLORS.textMuted };

  return (
    <div style={{ ...glassMorphStyle, padding: 20 }}>
      {sectionHead("FACT CHECKER", "AI Verification Engine", COLORS.green)}
      <div style={{ fontSize: 12, color: COLORS.textSecondary, marginBottom: 16 }}>Ask Saturday to verify any claim, news story, or information.</div>
      <div style={{ display: "flex", gap: 10, marginBottom: 16 }}>
        <input
          value={query}
          onChange={e => setQuery(e.target.value)}
          onKeyDown={e => e.key === "Enter" && check()}
          placeholder="Enter a claim to verify..."
          style={{
            flex: 1, background: "rgba(0,0,0,0.4)", border: `1px solid ${COLORS.border}`,
            borderRadius: 8, padding: "10px 14px", color: COLORS.textPrimary, fontSize: 13,
            fontFamily: "'Space Grotesk', sans-serif", outline: "none",
          }}
        />
        <button
          onClick={check}
          disabled={loading}
          style={{
            padding: "10px 20px", background: `${COLORS.green}20`, border: `1px solid ${COLORS.green}50`,
            color: COLORS.green, borderRadius: 8, cursor: loading ? "wait" : "pointer", fontSize: 13, fontWeight: 600,
          }}
        >
          {loading ? "Analyzing..." : "Verify"}
        </button>
      </div>

      {loading && (
        <div style={{ textAlign: "center", padding: "24px 0", color: COLORS.textSecondary, fontSize: 12, fontFamily: "'Space Mono', monospace" }}>
          <div style={{ animation: "pulse 1s infinite" }}>SATURDAY ANALYZING CLAIM...</div>
        </div>
      )}

      {result && (
        <div style={{ background: "rgba(0,0,0,0.4)", border: `1px solid ${verdictColors[result.verdict] || COLORS.border}30`, borderRadius: 10, padding: 16, animation: "floatIn 0.4s ease" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 14 }}>
            <div style={{
              fontSize: 22, fontWeight: 700, color: verdictColors[result.verdict] || COLORS.textPrimary,
              fontFamily: "'Space Mono', monospace", letterSpacing: "0.1em",
            }}>{result.verdict}</div>
            <div style={{ display: "flex", flexDirection: "column" }}>
              <div style={{ fontSize: 10, color: COLORS.textMuted, marginBottom: 4 }}>Confidence</div>
              <div style={{ background: COLORS.border, borderRadius: 4, width: 100, height: 6, overflow: "hidden" }}>
                <div style={{ width: `${result.confidence}%`, height: "100%", background: verdictColors[result.verdict] || COLORS.cyan, transition: "width 1s ease" }} />
              </div>
              <div style={{ fontSize: 10, color: COLORS.textSecondary, marginTop: 2 }}>{result.confidence}%</div>
            </div>
            <div style={{ marginLeft: "auto", fontSize: 11 }}>
              Source reliability: <span style={{ color: COLORS.cyan, fontWeight: 600 }}>{result.sourceReliability}</span>
            </div>
          </div>
          <div style={{ fontSize: 13, color: COLORS.textPrimary, marginBottom: 12, lineHeight: 1.6 }}>{result.explanation}</div>
          {result.evidence?.length > 0 && (
            <div>
              <div style={{ fontSize: 10, color: COLORS.textMuted, letterSpacing: "0.1em", marginBottom: 8 }}>SUPPORTING EVIDENCE</div>
              {result.evidence.map((ev, i) => (
                <div key={i} style={{ display: "flex", gap: 8, marginBottom: 6, fontSize: 12, color: COLORS.textSecondary }}>
                  <span style={{ color: COLORS.green }}>›</span>{ev}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function InvestigationCenter({ websites = [] }) {
  const top = [...websites].sort((a, b) => b.risk - a.risk)[0];
  const inv = {
    domain: top?.url || "No website incident",
    source: top?.source || "Local",
    reputation: top?.risk || 0,
    indicators: top ? [top.reason, `Status: ${top.action}`, `Source: ${top.source}`] : ["No website route has been blocked yet"],
    verdict: top ? (top.risk >= 70 ? "BLOCKED" : "SUSPICIOUS") : "WAITING",
  };

  return (
    <div style={{ ...glassMorphStyle, padding: 20 }}>
      {sectionHead("INVESTIGATION CENTER", `Case: ${inv.domain}`, COLORS.cyan)}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 16 }}>
        {[
          { label: "Source", value: inv.source, color: COLORS.cyan },
          { label: "Signal Count", value: websites.length, color: COLORS.amber },
          { label: "Reputation Score", value: inv.reputation, color: COLORS.red },
          { label: "Verdict", value: inv.verdict, color: COLORS.red },
        ].map((item, i) => (
          <div key={i} style={{ background: "rgba(0,0,0,0.3)", border: `1px solid ${item.color}30`, borderRadius: 8, padding: 12 }}>
            <div style={{ fontSize: 10, color: COLORS.textMuted, marginBottom: 4 }}>{item.label}</div>
            <div className="mono" style={{ fontSize: 16, fontWeight: 700, color: item.color }}>{item.value}</div>
          </div>
        ))}
      </div>
      <div style={{ marginBottom: 12 }}>
        <div style={{ fontSize: 11, color: COLORS.textMuted, letterSpacing: "0.1em", marginBottom: 8 }}>THREAT INDICATORS</div>
        {inv.indicators.map((ind, i) => (
          <div key={i} style={{ display: "flex", gap: 8, padding: "6px 0", borderBottom: `1px solid ${COLORS.border}30`, fontSize: 12, color: COLORS.textSecondary }}>
            <span style={{ color: COLORS.red }}>⚠</span>{ind}
          </div>
        ))}
      </div>
    </div>
  );
}

function ThreatWarningModal({ onClose, website }) {
  const active = website || { url: "No blocked website yet", risk: 0, reason: "Saturday has not intercepted a live route in this run.", reputation: "Waiting" };
  return (
    <div style={{
      position: "fixed", inset: 0, zIndex: 1000,
      background: "rgba(0,0,0,0.92)",
      display: "flex", alignItems: "center", justifyContent: "center",
      animation: "modalIn 0.3s ease",
      backdropFilter: "blur(8px)",
    }}>
      {/* Scanline effect */}
      <div style={{
        position: "absolute", inset: 0, overflow: "hidden", pointerEvents: "none",
        background: "repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(255,61,90,0.03) 2px, rgba(255,61,90,0.03) 4px)",
      }} />

      <div style={{
        width: 480, background: "rgba(10, 6, 12, 0.98)",
        border: `1px solid ${COLORS.red}60`,
        borderRadius: 16,
        padding: 32,
        animation: `warningPulse 2s ease infinite, modalIn 0.3s ease`,
        position: "relative",
        overflow: "hidden",
      }}>
        {/* Top glow */}
        <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 2, background: `linear-gradient(90deg, transparent, ${COLORS.red}, transparent)` }} />

        <div style={{ textAlign: "center", marginBottom: 24 }}>
          <div style={{ fontSize: 48, marginBottom: 8, animation: "pulse 1s infinite" }}>⚠️</div>
          <div className="mono" style={{ fontSize: 11, color: COLORS.red, letterSpacing: "0.3em", marginBottom: 8 }}>SATURDAY SECURITY ALERT</div>
          <div style={{ fontSize: 22, fontWeight: 700, color: COLORS.textPrimary, marginBottom: 4 }}>Suspicious Website Detected</div>
          <div style={{ fontSize: 13, color: COLORS.textSecondary }}>{active.reputation}</div>
        </div>

        <div style={{ background: "rgba(255,61,90,0.08)", border: `1px solid ${COLORS.red}30`, borderRadius: 10, padding: 16, marginBottom: 20 }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 10 }}>
            <div>
              <div style={{ fontSize: 10, color: COLORS.textMuted, marginBottom: 4 }}>DETECTED DOMAIN</div>
              <div className="mono" style={{ fontSize: 16, color: COLORS.red, fontWeight: 700 }}>{active.url}</div>
            </div>
            <div>
              <div style={{ fontSize: 10, color: COLORS.textMuted, marginBottom: 4 }}>SOURCE</div>
              <div className="mono" style={{ fontSize: 16, color: COLORS.green, fontWeight: 700 }}>{active.source || "Saturday"}</div>
            </div>
            <div>
              <div style={{ fontSize: 10, color: COLORS.textMuted, marginBottom: 4 }}>RISK SCORE</div>
              <div className="mono" style={{ fontSize: 16, color: COLORS.red, fontWeight: 700 }}>{active.risk}/100</div>
            </div>
          </div>
        </div>

        <div style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 11, color: COLORS.textMuted, letterSpacing: "0.1em", marginBottom: 10 }}>DETECTION REASONS</div>
          {[active.reason].filter(Boolean).map((r, i) => (
            <div key={i} style={{ display: "flex", gap: 10, marginBottom: 8, fontSize: 13, color: COLORS.textSecondary }}>
              <span style={{ color: COLORS.red, flexShrink: 0 }}>•</span>{r}
            </div>
          ))}
        </div>

        {/* Mascot message */}
        <div style={{ background: "rgba(0,200,255,0.05)", border: `1px solid ${COLORS.cyan}20`, borderRadius: 8, padding: 12, marginBottom: 20, display: "flex", gap: 10, alignItems: "flex-start" }}>
          <div style={{ fontSize: 24, flexShrink: 0 }}>🤖</div>
          <div style={{ fontSize: 12, color: COLORS.textSecondary, lineHeight: 1.6 }}>
            <span style={{ color: COLORS.cyan, fontWeight: 600 }}>Saturday says: </span>
            Saturday paused this route because the live backend scored it above the review threshold.
          </div>
        </div>

        <div style={{ display: "flex", gap: 12 }}>
          <button
            onClick={onClose}
            style={{
              flex: 1, padding: "12px", background: COLORS.green, color: "#000",
              border: "none", borderRadius: 8, fontWeight: 700, fontSize: 14, cursor: "pointer",
              fontFamily: "'Space Grotesk', sans-serif",
            }}>
            ← Leave Site (Safe)
          </button>
          <button
            onClick={onClose}
            style={{
              padding: "12px 20px", background: "transparent",
              border: `1px solid ${COLORS.textMuted}`, color: COLORS.textMuted,
              borderRadius: 8, fontSize: 13, cursor: "pointer",
              fontFamily: "'Space Grotesk', sans-serif",
            }}>
            Continue Anyway
          </button>
        </div>
      </div>
    </div>
  );
}

function EmailDetailPanel({ email, onClose, onAction }) {
  return (
    <div style={{
      position: "fixed", top: 0, right: 0, bottom: 0, width: 380, zIndex: 200,
      background: "rgba(8, 12, 20, 0.98)",
      border: `1px solid ${COLORS.border}`,
      borderRight: "none",
      boxShadow: `-20px 0 60px rgba(0,0,0,0.8)`,
      padding: 24, overflowY: "auto",
      animation: "floatIn 0.3s ease",
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
        <div style={{ fontSize: 14, fontWeight: 700, color: COLORS.textPrimary }}>Email Investigation</div>
        <button onClick={onClose} style={{ background: "none", border: "none", color: COLORS.textSecondary, cursor: "pointer", fontSize: 18 }}>✕</button>
      </div>

      <div style={{ background: "rgba(0,0,0,0.4)", border: `1px solid ${COLORS.red}30`, borderRadius: 10, padding: 14, marginBottom: 16 }}>
        <div style={{ fontSize: 11, color: COLORS.textMuted, marginBottom: 4 }}>From</div>
        <div className="mono" style={{ fontSize: 12, color: COLORS.red }}>{email.from}</div>
        <div style={{ marginTop: 8, fontSize: 13, fontWeight: 600, color: COLORS.textPrimary }}>{email.subject}</div>
      </div>

      <div style={{ marginBottom: 16 }}>
        <div style={{ fontSize: 11, color: COLORS.textMuted, letterSpacing: "0.1em", marginBottom: 10 }}>WHY IT WAS FLAGGED</div>
        {email.reasons.map((r, i) => (
          <div key={i} style={{ display: "flex", gap: 8, padding: "8px 0", borderBottom: `1px solid ${COLORS.border}30`, fontSize: 13, color: COLORS.textSecondary }}>
            <span style={{ color: COLORS.amber }}>⚠</span>{r}
          </div>
        ))}
      </div>

      <div style={{ marginBottom: 16 }}>
        <div style={{ fontSize: 11, color: COLORS.textMuted, letterSpacing: "0.1em", marginBottom: 10 }}>RISK ASSESSMENT</div>
        <div style={{ background: "rgba(0,0,0,0.3)", borderRadius: 8, padding: 14 }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
            <span style={{ fontSize: 12, color: COLORS.textSecondary }}>Risk Score</span>
            <RiskBadge score={email.risk} size="lg" />
          </div>
          <div style={{ background: COLORS.border, borderRadius: 4, height: 6, overflow: "hidden" }}>
            <div style={{ width: `${email.risk}%`, height: "100%", background: getRiskColor(email.risk) }} />
          </div>
        </div>
      </div>

      <div style={{ marginBottom: 16 }}>
        <div style={{ fontSize: 11, color: COLORS.textMuted, letterSpacing: "0.1em", marginBottom: 10 }}>RECOMMENDED ACTIONS</div>
        <div style={{ fontSize: 13, color: COLORS.textSecondary, lineHeight: 1.7 }}>
          Do not click any links or open attachments. Block the sender domain and report as phishing. This email pattern matches known credential harvesting campaigns targeting your industry.
        </div>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        <button onClick={() => onAction?.("QUARANTINE_EMAIL", email.id)} style={{ padding: "10px", background: `${COLORS.red}20`, border: `1px solid ${COLORS.red}50`, color: COLORS.red, borderRadius: 8, cursor: "pointer", fontSize: 13, fontWeight: 600 }}>Quarantine Locally</button>
        <button onClick={() => onAction?.("BLOCK_SENDER", email.id)} style={{ padding: "10px", background: `${COLORS.amber}10`, border: `1px solid ${COLORS.amber}40`, color: COLORS.amber, borderRadius: 8, cursor: "pointer", fontSize: 13 }}>Block Sender Domain</button>
        <button onClick={onClose} style={{ padding: "10px", background: "transparent", border: `1px solid ${COLORS.border}`, color: COLORS.textSecondary, borderRadius: 8, cursor: "pointer", fontSize: 13 }}>Close</button>
      </div>
    </div>
  );
}

function AssistantWidget({ onRefresh }) {
  const [open, setOpen] = useState(false);
  const [msg, setMsg] = useState("");
  const [msgs, setMsgs] = useState([
    { role: "ai", text: "Saturday online. How can I protect you today?" },
  ]);
  const [loading, setLoading] = useState(false);
  const msgsRef = useRef(null);

  useEffect(() => { if (msgsRef.current) msgsRef.current.scrollTop = msgsRef.current.scrollHeight; }, [msgs]);

  const send = async () => {
    if (!msg.trim() || loading) return;
    const userMsg = msg;
    setMsg("");
    setMsgs(prev => [...prev, { role: "user", text: userMsg }]);
    setLoading(true);
    try {
      const data = await saturdayApi("/api/command", { message: userMsg });
      setMsgs(prev => [...prev, { role: "ai", text: data.message || "Done." }]);
      onRefresh?.();
    } catch {
      setMsgs(prev => [...prev, { role: "ai", text: "Connection error. Please try again." }]);
    }
    setLoading(false);
  };

  return (
    <div style={{ position: "fixed", bottom: 20, right: 20, zIndex: 300 }}>
      {open && (
        <div style={{
          width: 320, height: 420,
          background: "rgba(8, 12, 22, 0.98)",
          border: `1px solid ${COLORS.cyan}40`,
          borderRadius: 16,
          marginBottom: 12,
          display: "flex", flexDirection: "column",
          animation: "modalIn 0.3s ease",
          boxShadow: `0 20px 60px rgba(0,0,0,0.8), 0 0 30px ${COLORS.cyan}15`,
        }}>
          <div style={{ padding: "14px 16px", borderBottom: `1px solid ${COLORS.border}`, display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ width: 32, height: 32, borderRadius: "50%", background: `${COLORS.cyan}20`, border: `1px solid ${COLORS.cyan}60`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16 }}>🤖</div>
            <div>
              <div style={{ fontSize: 13, fontWeight: 600, color: COLORS.textPrimary }}>Saturday</div>
              <div style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 10, color: COLORS.cyan }}>
                <div style={{ width: 5, height: 5, borderRadius: "50%", background: COLORS.cyan, animation: "pulse 1.5s infinite" }} />Online
              </div>
            </div>
            <button onClick={() => setOpen(false)} style={{ marginLeft: "auto", background: "none", border: "none", color: COLORS.textMuted, cursor: "pointer", fontSize: 16 }}>✕</button>
          </div>
          <div ref={msgsRef} style={{ flex: 1, overflowY: "auto", padding: 12, display: "flex", flexDirection: "column", gap: 10 }}>
            {msgs.map((m, i) => (
              <div key={i} style={{ display: "flex", justifyContent: m.role === "user" ? "flex-end" : "flex-start" }}>
                <div style={{
                  maxWidth: "80%", padding: "8px 12px", borderRadius: m.role === "user" ? "12px 12px 4px 12px" : "12px 12px 12px 4px",
                  background: m.role === "user" ? `${COLORS.cyan}20` : "rgba(0,0,0,0.4)",
                  border: `1px solid ${m.role === "user" ? COLORS.cyan + "40" : COLORS.border}`,
                  fontSize: 12, color: COLORS.textPrimary, lineHeight: 1.6,
                }}>
                  {m.text}
                </div>
              </div>
            ))}
            {loading && (
              <div style={{ display: "flex", gap: 4, padding: "8px 12px" }}>
                {[0, 1, 2].map(i => <div key={i} style={{ width: 6, height: 6, borderRadius: "50%", background: COLORS.cyan, animation: `pulse 1s infinite ${i * 0.2}s` }} />)}
              </div>
            )}
          </div>
          <div style={{ padding: "10px 12px", borderTop: `1px solid ${COLORS.border}`, display: "flex", gap: 8 }}>
            <input
              value={msg}
              onChange={e => setMsg(e.target.value)}
              onKeyDown={e => e.key === "Enter" && send()}
              placeholder="Ask Saturday anything..."
              style={{ flex: 1, background: "transparent", border: "none", color: COLORS.textPrimary, fontSize: 12, fontFamily: "'Space Grotesk', sans-serif", outline: "none" }}
            />
            <button onClick={send} style={{ background: `${COLORS.cyan}20`, border: `1px solid ${COLORS.cyan}50`, color: COLORS.cyan, borderRadius: 8, padding: "6px 12px", cursor: "pointer", fontSize: 12 }}>→</button>
          </div>
        </div>
      )}
      <button
        onClick={() => setOpen(!open)}
        style={{
          width: 52, height: 52, borderRadius: "50%",
          background: `linear-gradient(135deg, ${COLORS.cyan}30, #7b2dff40)`,
          border: `2px solid ${COLORS.cyan}60`,
          cursor: "pointer", fontSize: 22,
          boxShadow: `0 0 20px ${COLORS.cyan}30`,
          display: "flex", alignItems: "center", justifyContent: "center",
          position: "relative",
        }}
      >
        🤖
        <div style={{ position: "absolute", top: 0, right: 0, width: 14, height: 14, background: COLORS.green, borderRadius: "50%", border: "2px solid #080c14", animation: "pulse 2s infinite" }} />
      </button>
    </div>
  );
}

export default function Saturday() {
  const [activeNav, setActiveNav] = useState("dashboard");
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [showThreatModal, setShowThreatModal] = useState(false);
  const [emailDetail, setEmailDetail] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [aiEnabled, setAiEnabled] = useState(false);
  const [loadError, setLoadError] = useState("");

  const refreshIncidents = async () => {
    try {
      const data = await saturdayApi("/api/incidents");
      setIncidents(data.incidents || []);
      setAiEnabled(Boolean(data.ai_enabled));
      setLoadError("");
    } catch (error) {
      setLoadError(error.message || "Could not load Saturday incidents.");
    }
  };

  useEffect(() => {
    refreshIncidents();
    const timer = setInterval(refreshIncidents, 10000);
    return () => clearInterval(timer);
  }, []);

  const threats = mapThreats(incidents);
  const emails = mapEmails(incidents);
  const websites = mapWebsites(incidents);
  const radarData = mapRadarData(incidents);
  const topWebsite = [...websites].sort((a, b) => b.risk - a.risk)[0];
  const topIncident = [...incidents].sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0))[0];
  const briefing = incidents.length
    ? [
        `Saturday is tracking ${incidents.length} live event${incidents.length === 1 ? "" : "s"}.`,
        `${emails.length} email signal${emails.length === 1 ? "" : "s"} and ${websites.length} website route${websites.length === 1 ? "" : "s"} are in local memory.`,
        `${incidents.filter(item => item.hackarena).length} event${incidents.filter(item => item.hackarena).length === 1 ? "" : "s"} include HackArena threat intel.`,
        topIncident ? `Highest risk: ${topIncident.title || "Security event"} (${topIncident.risk_score}/100).` : "",
      ].filter(Boolean).join("\n\n")
    : loadError || "No live incidents yet.";

  const runIncidentAction = async (intent, target) => {
    if (!target) return;
    await saturdayApi("/api/action", { intent, target });
    await refreshIncidents();
  };

  return (
    <div style={{ height: "100vh", display: "flex", flexDirection: "column", background: COLORS.bg, overflow: "hidden" }}>
      <style>{css}</style>

      {/* Background grid */}
      <div style={{
        position: "fixed", inset: 0, pointerEvents: "none", zIndex: 0,
        backgroundImage: `linear-gradient(${COLORS.border} 1px, transparent 1px), linear-gradient(90deg, ${COLORS.border} 1px, transparent 1px)`,
        backgroundSize: "42px 42px",
        opacity: 0.35,
      }} />

      <div style={{ display: "flex", flex: 1, overflow: "hidden", position: "relative", zIndex: 1 }}>
        <Sidebar activeNav={activeNav} setActiveNav={setActiveNav} sidebarOpen={sidebarOpen} />

        <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
          <Header sidebarOpen={sidebarOpen} setSidebarOpen={setSidebarOpen} setShowThreatModal={setShowThreatModal} incidents={incidents} aiEnabled={aiEnabled} />

          {/* Main content */}
          <div style={{ flex: 1, overflowY: "auto", padding: 20, display: "flex", flexDirection: "column", gap: 16 }}>

            {activeNav === "dashboard" && (
              <>
                <HeroCard incidents={incidents} />
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
                  <AIBriefing briefing={briefing} />
                  <RadarChart radarData={radarData} />
                </div>
                <ThreatTimeline threats={threats} />
              </>
            )}

            {activeNav === "timeline" && <ThreatTimeline threats={threats} />}

            {activeNav === "email" && (
              <EmailPanel emails={emails} setEmailDetail={setEmailDetail} onAction={runIncidentAction} />
            )}

            {activeNav === "websites" && (
              <>
                <WebsitePanel websites={websites} />
                <InvestigationCenter websites={websites} />
              </>
            )}

            {activeNav === "investigations" && <InvestigationCenter websites={websites} />}

            {activeNav === "factcheck" && <FactChecker />}

            {activeNav === "reports" && (
              <div style={{ ...glassMorphStyle, padding: 32, textAlign: "center" }}>
                {sectionHead("REPORTS", "Security Reports", COLORS.cyan)}
                <div style={{ color: COLORS.textSecondary, fontSize: 13, marginTop: 24 }}>
                  Weekly and monthly security summaries, threat intelligence reports, and investigation case files will appear here.
                </div>
              </div>
            )}

            {activeNav === "settings" && (
              <div style={{ ...glassMorphStyle, padding: 32, textAlign: "center" }}>
                {sectionHead("SETTINGS", "Configuration", COLORS.textSecondary)}
                <div style={{ color: COLORS.textSecondary, fontSize: 13, marginTop: 24 }}>
                  Configure Saturday's monitoring preferences, notification settings, and AI behavior.
                </div>
              </div>
            )}

          </div>
        </div>
      </div>

      {showThreatModal && <ThreatWarningModal onClose={() => setShowThreatModal(false)} website={topWebsite} />}
      {emailDetail && <EmailDetailPanel email={emailDetail} onClose={() => setEmailDetail(null)} onAction={runIncidentAction} />}
      <AssistantWidget onRefresh={refreshIncidents} />
    </div>
  );
}
