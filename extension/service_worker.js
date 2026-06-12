const API_CANDIDATES = Array.from({length: 20}, (_, index) => `http://127.0.0.1:${8765 + index}`);
const BLOCK_THRESHOLD = 70;
const recentChecks = new Map();
let activeApiBase = null;

function skipUrl(url) {
  return (
    !url ||
    url.startsWith("chrome://") ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("edge://") ||
    url.startsWith("about:") ||
    url.startsWith("file://") ||
    /^https?:\/\/(?:127\.0\.0\.1|localhost):87[6-8]\d\//.test(url)
  );
}

function recentlyChecked(url) {
  const now = Date.now();
  const expires = recentChecks.get(url);
  if (expires && expires > now) return true;
  recentChecks.set(url, now + 2500);
  for (const [key, value] of recentChecks.entries()) {
    if (value < now) recentChecks.delete(key);
  }
  return false;
}

async function checkUrl(url) {
  const apiBase = await resolveApiBase();
  if (!apiBase) throw new Error("Saturday local engine is not reachable");
  const response = await fetch(`${apiBase}/api/check-url`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({url, source: "extension"})
  });
  const data = await response.json();
  return {...data, apiBase};
}

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

chrome.webNavigation.onBeforeNavigate.addListener(async details => {
  if (details.frameId !== 0) return;
  const url = details.url;
  if (skipUrl(url) || recentlyChecked(url)) return;

  try {
    const result = await checkUrl(url);
    if (result.allow_navigation) return;
    if (result.risk_score >= BLOCK_THRESHOLD) {
      const warningUrl = `${result.apiBase}/warning?url=${encodeURIComponent(url)}&from=extension`;
      await chrome.tabs.update(details.tabId, {url: warningUrl});
    }
  } catch (error) {
    console.warn("Saturday local engine is not reachable", error);
  }
});
