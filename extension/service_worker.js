const API_BASE = "http://127.0.0.1:8765";
const BLOCK_THRESHOLD = 70;
const recentChecks = new Map();

function skipUrl(url) {
  return (
    !url ||
    url.startsWith("chrome://") ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("edge://") ||
    url.startsWith("about:") ||
    url.startsWith("file://") ||
    url.startsWith(`${API_BASE}/`) ||
    url.includes("127.0.0.1:8765") ||
    url.includes("localhost:8765")
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
  const response = await fetch(`${API_BASE}/api/check-url`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({url, source: "extension"})
  });
  return response.json();
}

chrome.webNavigation.onBeforeNavigate.addListener(async details => {
  if (details.frameId !== 0) return;
  const url = details.url;
  if (skipUrl(url) || recentlyChecked(url)) return;

  try {
    const result = await checkUrl(url);
    if (result.allow_navigation) return;
    if (result.risk_score >= BLOCK_THRESHOLD) {
      const warningUrl = `${API_BASE}/warning?url=${encodeURIComponent(url)}&from=extension`;
      await chrome.tabs.update(details.tabId, {url: warningUrl});
    }
  } catch (error) {
    console.warn("Saturday local engine is not reachable", error);
  }
});
