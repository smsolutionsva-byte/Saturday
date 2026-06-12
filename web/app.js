const state = {
  incidents: [],
  aiEnabled: false
};

const chatLog = document.querySelector("#chatLog");
const commandForm = document.querySelector("#commandForm");
const commandInput = document.querySelector("#commandInput");
const incidentTemplate = document.querySelector("#incidentTemplate");

function riskClass(score) {
  if (score >= 85) return "critical";
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  return "low";
}

function targetOf(incident) {
  return incident.sender || incident.url || incident.target || "Unknown target";
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

async function loadIncidents() {
  const data = await api("/api/incidents");
  state.incidents = data.incidents || [];
  state.aiEnabled = data.ai_enabled;
  render();
}

function render() {
  document.querySelector("#aiBadge").textContent = state.aiEnabled ? "OpenRouter on" : "local mode";
  document.querySelector("#incidentCount").textContent = `${state.incidents.length} event${state.incidents.length === 1 ? "" : "s"}`;

  const top = [...state.incidents].sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))[0];
  document.querySelector("#heroRisk").textContent = top ? top.risk_score : "--";
  renderTopRisk(top);
  renderTimeline();
  renderIncidentList();
}

function renderTopRisk(top) {
  const container = document.querySelector("#topRisk");
  if (!top) {
    container.className = "top-risk-empty";
    container.textContent = "No incidents yet. Run the demo scan to wake the system.";
    return;
  }
  container.className = `top-risk-card ${riskClass(top.risk_score)}`;
  container.innerHTML = `
    <div class="score-ring">${top.risk_score}</div>
    <div>
      <h3>${escapeHtml(top.title || "Security event")}</h3>
      <p>${escapeHtml(targetOf(top))}</p>
      <ul>${(top.reasons || []).slice(0, 3).map(reason => `<li>${escapeHtml(reason)}</li>`).join("")}</ul>
    </div>
  `;
}

function renderTimeline() {
  const timeline = document.querySelector("#timeline");
  if (!state.incidents.length) {
    timeline.innerHTML = `<div class="empty-note">Timeline is waiting for the first signal.</div>`;
    return;
  }
  timeline.innerHTML = state.incidents
    .slice(0, 8)
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

function renderIncidentList() {
  const list = document.querySelector("#incidentList");
  list.innerHTML = "";
  if (!state.incidents.length) {
    list.innerHTML = `<div class="empty-note">No local incidents stored yet.</div>`;
    return;
  }
  for (const incident of state.incidents) {
    const node = incidentTemplate.content.firstElementChild.cloneNode(true);
    node.classList.add(riskClass(incident.risk_score));
    node.querySelector(".risk-pill").textContent = `${incident.risk_score}`;
    node.querySelector(".incident-title").textContent = incident.title || "Security event";
    node.querySelector(".incident-status").textContent = incident.status || "pending";
    node.querySelector(".incident-target").textContent = targetOf(incident);
    const reasons = node.querySelector(".incident-reasons");
    for (const reason of (incident.reasons || []).slice(0, 3)) {
      const item = document.createElement("li");
      item.textContent = reason;
      reasons.appendChild(item);
    }
    for (const button of node.querySelectorAll("[data-action]")) {
      const action = button.dataset.action;
      if (incident.kind !== "email" && action !== "SHOW_DETAILS") button.disabled = true;
      button.addEventListener("click", () => runAction(action, incident.id));
    }
    list.appendChild(node);
  }
}

async function runAction(intent, target) {
  const data = await api("/api/action", {intent, target});
  addChat("assistant", data.message || "Done.");
  await loadIncidents();
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
  const data = await api("/api/scan-demo", {});
  addChat("assistant", data.message);
  await loadIncidents();
});

document.querySelector("#scanImap").addEventListener("click", async () => {
  const data = await api("/api/scan-mail", {limit: 15});
  addChat("assistant", data.message);
  await loadIncidents();
});

document.querySelector("#simulateSite").addEventListener("click", () => {
  location.href = "/warning?url=https%3A%2F%2Fg00gle-login.xyz%2Faccounts%2Fverify";
});

document.querySelector("#refresh").addEventListener("click", loadIncidents);

document.querySelector("#reportBtn").addEventListener("click", async () => {
  const data = await api("/api/command", {message: "send me the full report"});
  addChat("assistant", data.message);
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
    await loadIncidents();
  } catch (error) {
    addChat("assistant", error.message);
  }
});

addChat("assistant", "I am awake. Try: check my mail, show me the highest risk event, quarantine that email, or send me the full report.");
loadIncidents();
