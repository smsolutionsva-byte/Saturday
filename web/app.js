const state = {
  incidents: [],
  aiEnabled: false,
  lastScan: null
};

const chatLog = document.querySelector("#chatLog");
const commandForm = document.querySelector("#commandForm");
const commandInput = document.querySelector("#commandInput");

function riskClass(score = 0) {
  if (score >= 85) return "critical";
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  return "low";
}

function targetOf(incident) {
  return incident.sender || incident.url || incident.target || "Unknown target";
}

function displayStatus(status = "pending") {
  return String(status).replaceAll("_", " ");
}

function sourceOf(incident) {
  if (incident.hackarena?.source) return "HackArena";
  if (incident.source === "imap") return "IMAP";
  if (incident.source === "extension") return "Extension";
  if (incident.source === "dashboard") return "Dashboard";
  return incident.source || "Local";
}

function addChat(who, text) {
  const item = document.createElement("div");
  item.className = `chat-line ${who}`;
  item.innerHTML = `<span>${who === "user" ? "You" : "Saturday"}</span><p></p>`;
  item.querySelector("p").textContent = text;
  chatLog.appendChild(item);
  chatLog.scrollTop = chatLog.scrollHeight;
}

async function api(path, payload = null) {
  const options = payload
    ? {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload)}
    : {};
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.message || "Request failed");
  return data;
}

async function loadHealth() {
  try {
    const data = await api("/api/health");
    const status = document.querySelector("#healthStatus");
    status.textContent = data.ok ? `online :${data.port}` : "offline";
    status.className = data.ok ? "badge good" : "badge bad";
    document.querySelector("#navStatus span").textContent = data.ok ? "System watching" : "Start Saturday";
  } catch {
    document.querySelector("#healthStatus").textContent = "offline";
    document.querySelector("#healthStatus").className = "badge bad";
    document.querySelector("#navStatus span").textContent = "Local engine offline";
  }
}

async function loadIncidents() {
  const data = await api("/api/incidents");
  state.incidents = data.incidents || [];
  state.aiEnabled = Boolean(data.ai_enabled);
  render();
}

function render() {
  const incidents = state.incidents;
  const emails = incidents.filter(item => item.kind === "email");
  const websites = incidents.filter(item => item.kind === "web");
  const risky = incidents.filter(item => Number(item.risk_score || 0) >= 40);
  const high = incidents.filter(item => Number(item.risk_score || 0) >= 70);
  const blocked = incidents.filter(item => {
    const status = String(item.status || "").toLowerCase();
    return status.includes("quarantined") || status.includes("blocked") || (item.kind === "web" && Number(item.risk_score || 0) >= 70);
  });
  const top = [...incidents].sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0))[0];

  document.querySelector("#aiBadge").textContent = state.aiEnabled ? "OpenRouter on" : "local mode";
  document.querySelector("#incidentCount").textContent = `${incidents.length} event${incidents.length === 1 ? "" : "s"}`;
  document.querySelector("#heroRisk").textContent = top ? top.risk_score : "--";
  document.querySelector("#statThreats").textContent = risky.length;
  document.querySelector("#statBlocked").textContent = blocked.length;
  document.querySelector("#statEmails").textContent = emails.length;
  document.querySelector("#statWeb").textContent = websites.length;

  const label = high.length ? "ALERT" : incidents.length ? "SECURE" : "READY";
  document.querySelector("#securityLabel").textContent = label;
  document.querySelector("#securityLabel").className = `status-word ${high.length ? "danger" : incidents.length ? "safe" : ""}`;
  document.querySelector("#securityMessage").textContent = high.length
    ? `${high.length} high-risk event${high.length === 1 ? "" : "s"} need review.`
    : incidents.length
      ? "No active high-risk pending route is dominating the queue."
      : "Saturday is connected to local incidents and waiting for a scan.";

  renderTopRisk(top);
  renderBriefing({incidents, emails, websites, high, top});
  renderTimeline(incidents);
  renderRadar({emails, websites, high, blocked, incidents});
  renderEmailList(emails);
  renderWebsiteTable(websites);
}

function renderTopRisk(top) {
  const container = document.querySelector("#topRisk");
  if (!top) {
    container.className = "empty-note";
    container.textContent = "No incidents yet.";
    return;
  }

  container.className = `top-risk-card ${riskClass(top.risk_score)}`;
  container.innerHTML = `
    <div class="score-ring">${escapeHtml(top.risk_score)}</div>
    <div>
      <div class="incident-kicker">${escapeHtml(sourceOf(top))} / ${escapeHtml(top.kind || "event")}</div>
      <h3>${escapeHtml(top.title || "Security event")}</h3>
      <p>${escapeHtml(targetOf(top))}</p>
      <ul>${(top.reasons || []).slice(0, 4).map(reason => `<li>${escapeHtml(reason)}</li>`).join("")}</ul>
    </div>
  `;
}

function renderBriefing({incidents, emails, websites, high, top}) {
  const briefing = document.querySelector("#briefingText");
  if (!incidents.length) {
    briefing.textContent = "No incidents are stored yet.\n\nRun an IMAP scan or trigger the browser guard to populate the live console.";
    return;
  }

  const imapCount = emails.filter(item => item.source === "imap").length;
  const hackArenaCount = incidents.filter(item => item.hackarena).length;
  const lines = [
    `Saturday is tracking ${incidents.length} local event${incidents.length === 1 ? "" : "s"}.`,
    `${emails.length} email signal${emails.length === 1 ? "" : "s"} (${imapCount} from IMAP).`,
    `${websites.length} website route${websites.length === 1 ? "" : "s"} analyzed.`,
    `${high.length} high-risk event${high.length === 1 ? "" : "s"} at or above the block threshold.`,
  ];
  if (hackArenaCount) {
    lines.push(`${hackArenaCount} verdict${hackArenaCount === 1 ? "" : "s"} include HackArena threat intel.`);
  }
  if (top) {
    lines.push("");
    lines.push(`Highest risk: ${top.title || "Security event"} (${top.risk_score}/100).`);
    lines.push((top.reasons || ["No reason recorded"])[0]);
  }
  if (state.lastScan) {
    lines.push("");
    lines.push(state.lastScan);
  }
  briefing.textContent = lines.join("\n");
}

function renderTimeline(incidents) {
  const timeline = document.querySelector("#timeline");
  if (!incidents.length) {
    timeline.innerHTML = `<div class="empty-note">Timeline is waiting for the first signal.</div>`;
    return;
  }

  timeline.innerHTML = incidents
    .slice(0, 10)
    .map(incident => `
      <div class="timeline-row ${riskClass(incident.risk_score)}">
        <time>${escapeHtml(incident.time_label || "--:--")}</time>
        <span></span>
        <div>
          <strong>${escapeHtml(incident.title || "Security event")}</strong>
          <p>${escapeHtml((incident.reasons || [])[0] || targetOf(incident))}</p>
        </div>
      </div>
    `)
    .join("");
}

function renderRadar({emails, websites, high, blocked, incidents}) {
  const rows = [
    {label: "Email", value: emails.length, color: "amber"},
    {label: "Web", value: websites.length, color: "cyan"},
    {label: "High Risk", value: high.length, color: "red"},
    {label: "Contained", value: blocked.length, color: "green"},
    {label: "HackArena", value: incidents.filter(item => item.hackarena).length, color: "purple"},
  ];
  const max = Math.max(1, ...rows.map(row => row.value));
  document.querySelector("#radarBars").innerHTML = rows.map(row => `
    <div class="radar-row ${row.color}">
      <span>${escapeHtml(row.label)}</span>
      <div><i style="width:${Math.max(8, Math.round((row.value / max) * 100))}%"></i></div>
      <strong>${row.value}</strong>
    </div>
  `).join("");
}

function renderEmailList(emails) {
  const list = document.querySelector("#emailList");
  const sorted = [...emails].sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0));
  if (!sorted.length) {
    list.innerHTML = `<div class="empty-note">No email incidents yet.</div>`;
    return;
  }

  list.innerHTML = sorted.map(email => incidentCard(email, true)).join("");
  bindIncidentActions(list);
}

function renderWebsiteTable(websites) {
  const table = document.querySelector("#websiteTable");
  const sorted = [...websites].sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0));
  if (!sorted.length) {
    table.innerHTML = `<tr><td colspan="4" class="empty-cell">No website incidents yet.</td></tr>`;
    return;
  }

  table.innerHTML = sorted.map(site => `
    <tr>
      <td class="mono danger-text">${escapeHtml(site.url || site.target || "Unknown route")}</td>
      <td><span class="risk-badge ${riskClass(site.risk_score)}">${escapeHtml(site.risk_score || 0)}</span></td>
      <td>${escapeHtml(sourceOf(site))}</td>
      <td><span class="status-badge">${escapeHtml(displayStatus(site.status))}</span></td>
    </tr>
  `).join("");
}

function incidentCard(incident, emailActions) {
  const reasons = (incident.reasons || []).slice(0, 3).map(reason => `<span>${escapeHtml(reason)}</span>`).join("");
  const actions = emailActions
    ? `
      <button data-action="SHOW_DETAILS" data-id="${escapeHtml(incident.id)}">Details</button>
      <button data-action="QUARANTINE_EMAIL" data-id="${escapeHtml(incident.id)}">Quarantine</button>
      <button data-action="ARCHIVE_EMAIL" data-id="${escapeHtml(incident.id)}">Archive</button>
      <button data-action="BLOCK_SENDER" data-id="${escapeHtml(incident.id)}">Block</button>
    `
    : "";

  return `
    <div class="incident-card ${riskClass(incident.risk_score)}">
      <div class="risk-pill">${escapeHtml(incident.risk_score || 0)}</div>
      <div class="incident-main">
        <div class="incident-title-row">
          <strong>${escapeHtml(incident.subject || incident.title || "Security event")}</strong>
          <span class="status-badge">${escapeHtml(displayStatus(incident.status))}</span>
        </div>
        <p>${escapeHtml(targetOf(incident))}</p>
        <div class="reason-chips">${reasons}</div>
        <div class="incident-actions">${actions}</div>
      </div>
    </div>
  `;
}

function bindIncidentActions(root) {
  for (const button of root.querySelectorAll("[data-action]")) {
    button.addEventListener("click", () => runAction(button.dataset.action, button.dataset.id));
  }
}

async function runAction(intent, target) {
  try {
    const data = await api("/api/action", {intent, target});
    addChat("assistant", data.message || "Done.");
    await loadIncidents();
  } catch (error) {
    addChat("assistant", error.message);
  }
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

document.querySelector("#scanDemo").addEventListener("click", async () => {
  try {
    const data = await api("/api/scan-demo", {});
    addChat("assistant", data.message);
    await loadIncidents();
  } catch (error) {
    addChat("assistant", error.message);
  }
});

document.querySelector("#scanImap").addEventListener("click", async () => {
  const status = document.querySelector("#imapStatus");
  status.textContent = "IMAP scanning";
  status.className = "badge warn";
  try {
    const data = await api("/api/scan-mail", {limit: 15});
    state.lastScan = data.ok
      ? `Last IMAP scan: ${data.scanned_count || 0} messages scanned, ${(data.created || []).length} suspicious events added or refreshed.`
      : data.message;
    status.textContent = data.ok ? "IMAP complete" : "IMAP failed";
    status.className = data.ok ? "badge good" : "badge bad";
    addChat("assistant", data.message);
    await loadIncidents();
  } catch (error) {
    status.textContent = "IMAP failed";
    status.className = "badge bad";
    addChat("assistant", error.message);
  }
});

document.querySelector("#simulateSite").addEventListener("click", () => {
  location.href = "/warning?url=https%3A%2F%2Fsecure-login.sentinelai-verification.com%2Fauth%2Flogin";
});

document.querySelector("#refresh").addEventListener("click", async () => {
  await loadHealth();
  await loadIncidents();
});

document.querySelector("#reportBtn").addEventListener("click", async () => {
  try {
    const data = await api("/api/command", {message: "send me the full report"});
    addChat("assistant", data.message);
  } catch (error) {
    addChat("assistant", error.message);
  }
});

commandForm.addEventListener("submit", async event => {
  event.preventDefault();
  const message = commandInput.value.trim();
  if (!message) return;
  addChat("user", message);
  commandInput.value = "";
  try {
    const data = await api("/api/command", {message});
    addChat("assistant", data.message || "Done.");
    if (data.scan) {
      state.lastScan = `Last IMAP scan: ${data.scan.scanned_count || 0} messages scanned, ${(data.scan.created || []).length} suspicious events added or refreshed.`;
    }
    await loadIncidents();
  } catch (error) {
    addChat("assistant", error.message);
  }
});

addChat("assistant", "Saturday online. Live incidents, IMAP scans, and browser guard signals will appear here.");
loadHealth();
loadIncidents().catch(error => addChat("assistant", error.message));
