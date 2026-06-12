const API_BASE = "http://127.0.0.1:8765";

async function refresh() {
  const status = document.querySelector("#status");
  try {
    const response = await fetch(`${API_BASE}/api/health`);
    const data = await response.json();
    status.textContent = data.ok
      ? `Online - ${data.incident_count} local event${data.incident_count === 1 ? "" : "s"}`
      : "Local engine not ready";
  } catch (error) {
    status.textContent = "Start Saturday first";
  }
}

document.querySelector("#openDashboard").addEventListener("click", () => {
  chrome.tabs.create({url: `${API_BASE}/`});
});

document.querySelector("#demoWarning").addEventListener("click", () => {
  chrome.tabs.create({url: `${API_BASE}/warning?url=${encodeURIComponent("https://g00gle-login.xyz/accounts/verify")}`});
});

refresh();
