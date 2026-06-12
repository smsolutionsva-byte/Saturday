const API_CANDIDATES = Array.from({length: 20}, (_, index) => `http://127.0.0.1:${8765 + index}`);
let activeApiBase = null;

async function resolveApiBase() {
  if (activeApiBase && await isHealthy(activeApiBase)) return activeApiBase;

  const stored = await chrome.storage.local.get("apiBase");
  if (stored.apiBase && await isHealthy(stored.apiBase)) {
    activeApiBase = stored.apiBase;
    return activeApiBase;
  }

  for (const candidate of API_CANDIDATES) {
    if (await isHealthy(candidate)) {
      activeApiBase = candidate;
      await chrome.storage.local.set({apiBase: candidate});
      return candidate;
    }
  }
  return null;
}

async function isHealthy(apiBase) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 650);
    const response = await fetch(`${apiBase}/api/health`, {signal: controller.signal});
    clearTimeout(timer);
    if (!response.ok) return false;
    const data = await response.json();
    if (!data.ok || data.app !== "Saturday") return false;
    const mascotResponse = await fetch(`${apiBase}/mascot-viewer.js`, {cache: "no-store"});
    return mascotResponse.ok;
  } catch (error) {
    return false;
  }
}

async function refresh() {
  const status = document.querySelector("#status");
  try {
    const apiBase = await resolveApiBase();
    if (!apiBase) throw new Error("Saturday not found");
    const response = await fetch(`${apiBase}/api/health`);
    const data = await response.json();
    status.textContent = data.ok
      ? `Online on ${new URL(apiBase).port} - ${data.incident_count} local event${data.incident_count === 1 ? "" : "s"}`
      : "Local engine not ready";
  } catch (error) {
    status.textContent = "Start Saturday first";
  }
}

document.querySelector("#openDashboard").addEventListener("click", async () => {
  const apiBase = await resolveApiBase();
  chrome.tabs.create({url: `${apiBase || API_CANDIDATES[0]}/`});
});

document.querySelector("#demoWarning").addEventListener("click", async () => {
  const apiBase = await resolveApiBase();
  chrome.tabs.create({url: `${apiBase || API_CANDIDATES[0]}/warning?url=${encodeURIComponent("https://g00gle-login.xyz/accounts/verify")}`});
});

refresh();
