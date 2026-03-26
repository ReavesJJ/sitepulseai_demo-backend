// ---------------------------
// SitePulseAI Frontend Logic (Modular JS)
// ---------------------------

const API_BASE = "https://sitepulseai-demo-backend.onrender.com";
const REFRESH_INTERVAL = 60000; // 60 seconds

// ---------------------------
// STATE
// ---------------------------
const state = {
  segments: {},       // { segment: [domains] }
  metrics: {}         // { domain: { uptime, latency, ssl, seo, vulnerabilities, traffic, segment } }
};

// ---------------------------
// UTILITY: UPDATE CARD CONTENT
// ---------------------------
function updateCard(id, content) {
  const el = document.getElementById(id);
  if (!el) return;
  el.innerHTML = content || "—";
}

// ---------------------------
// RENDER DASHBOARD
// ---------------------------
function renderDashboard() {
  const results = Object.values(state.metrics);

  let uptimeHTML = "";
  let latencyHTML = "";
  let sslHTML = "";
  let seoHTML = "";
  let vulnHTML = "";
  let trafficHTML = "";
  let summaryHTML = "";
  let recHTML = "";

  results.forEach(r => {
    const label = `[${r.segment}] ${r.domain}`;

    uptimeHTML += `${label} → ${r.uptime?.status || "—"}<br>`;
    latencyHTML += `${label} → ${r.latency?.load_time ? Math.round(r.latency.load_time * 1000) : "--"} ms<br>`;
    sslHTML += `${label} → ${r.ssl?.valid ? "Valid" : "Invalid"}<br>`;
    seoHTML += `${label} → ${r.seo?.score ?? "—"}<br>`;
    vulnHTML += `${label} → ${r.vulnerabilities?.count ?? 0}<br>`;
    trafficHTML += `${label} → ${r.traffic?.visits ?? "--"}<br>`;
    summaryHTML += `${label} → ${r.uptime?.status === "up" ? "Operational" : "Down"}, ${r.latency?.load_time ? Math.round(r.latency.load_time * 1000) : "--"} ms<br>`;

    if (r.vulnerabilities?.count > 0) recHTML += `${label}: Patch ${r.vulnerabilities.count} vulnerabilities<br>`;
    if (!r.ssl?.valid) recHTML += `${label}: SSL misconfiguration detected<br>`;
    if (!r.seo?.score) recHTML += `${label}: SEO improvements recommended<br>`;
  });

  // Inject into existing cards
  updateCard("uptime", uptimeHTML);
  updateCard("response-time", latencyHTML);
  updateCard("ssl-status", sslHTML);
  updateCard("seo-score", seoHTML);
  updateCard("vulnerabilities", vulnHTML);
  updateCard("traffic", trafficHTML);
  updateCard("ai-summary", summaryHTML);
  updateCard("ai-recommendations", recHTML || "No critical issues detected.");
}

// ---------------------------
// FETCH METRICS FOR ONE DOMAIN
// ---------------------------
async function fetchMetrics(domain, segment = "default") {
  try {
    const [uptime, latency, ssl, seo, vulnerabilities, traffic] = await Promise.all([
      fetch(`${API_BASE}/uptime/${domain}`).then(r => r.json()),
      fetch(`${API_BASE}/latency/${domain}`).then(r => r.json()),
      fetch(`${API_BASE}/ssl/${domain}`).then(r => r.json()),
      fetch(`${API_BASE}/seo/${domain}`).then(r => r.json()),
      fetch(`${API_BASE}/vulnerabilities/${domain}`).then(r => r.json()),
      fetch(`${API_BASE}/traffic/${domain}`).then(r => r.json())
    ]);

    state.metrics[domain] = { domain, segment, uptime, latency, ssl, seo, vulnerabilities, traffic };
  } catch (err) {
    console.error(`Telemetry fetch failed for ${domain}:`, err);
    state.metrics[domain] = { domain, segment, uptime: { status: "Error" } };
  }
}

// ---------------------------
// LOAD SEGMENTS
// ---------------------------
async function loadSegments() {
  try {
    const res = await fetch(`${API_BASE}/segments`);
    const data = await res.json();
    state.segments = data.segments ?? { default: [] };
  } catch (err) {
    console.error("Segments fetch failed:", err);
    state.segments = { default: [] };
  }
}

// ---------------------------
// MONITORING LOOP
// ---------------------------
async function monitoringLoop() {
  const promises = [];

  for (const segment in state.segments) {
    const domains = state.segments[segment] ?? [];
    domains.forEach(domain => promises.push(fetchMetrics(domain, segment)));
  }

  await Promise.all(promises);
  renderDashboard();
}

// ---------------------------
// ADD DOMAIN FUNCTION
// ---------------------------
async function addDomain(domain) {
  if (!domain) return;

  const payload = { domain, segment: "default" };
  try {
    const res = await fetch(`${API_BASE}/add_url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Failed to add domain");

    console.log("Domain added:", domain);

    await loadSegments();
    await fetchMetrics(domain, "default");
    renderDashboard();

  } catch (err) {
    console.error("Add domain failed:", err);
  }
}

// ---------------------------
// INIT EVENTS
// ---------------------------
document.addEventListener("DOMContentLoaded", () => {
  const addButton = document.getElementById("add-url-button");
  const websiteInput = document.getElementById("website-url-input");

  if (addButton && websiteInput) {
    addButton.addEventListener("click", () => {
      const domain = websiteInput.value.trim();
      if (domain) addDomain(domain);
      websiteInput.value = "";
    });
  } else {
    console.warn("Add button or input not found");
  }
});

// ---------------------------
// INIT DASHBOARD
// ---------------------------
async function init() {
  await loadSegments();
  await monitoringLoop(); // immediate run
  setInterval(monitoringLoop, REFRESH_INTERVAL); // continuous monitoring
}

init();