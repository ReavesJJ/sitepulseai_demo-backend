// ---------------------------
// SitePulseAI Frontend Logic (Modular JS)
// ---------------------------
// dashboard.js
const API_BASE = "https://sitepulseai-demo-backend.onrender.com";

// ---------------------------
// DOM ELEMENTS
// ---------------------------
const websiteInput = document.getElementById("website-url");
const addInput = document.getElementById("multi-url-input");
const addButton = document.getElementById("addButton");

// CARD ELEMENTS
const uptimeEl = document.getElementById("uptime");
const responseEl = document.getElementById("response-time");
const seoEl = document.getElementById("seo-score");
const sslEl = document.getElementById("ssl-status");
const trafficEl = document.getElementById("traffic");
const vulnEl = document.getElementById("vulnerabilities");
const summaryEl = document.getElementById("ai-summary");
const recEl = document.getElementById("ai-recommendations");

// ---------------------------
// STATE
// ---------------------------
let segments = {};
const REFRESH_INTERVAL = 60000; // 60s

// ---------------------------
// HELPERS
// ---------------------------
function normalizeDomain(domain) {
  if (!domain) return null;
  return domain.replace(/^https?:\/\//, "").replace(/\/$/, "").trim();
}

// ---------------------------
// LOAD SEGMENTS FROM BACKEND
// ---------------------------
async function loadDomains() {
  try {
    const res = await fetch(`${API_BASE}/segments`);
    if (!res.ok) throw new Error("Segments endpoint failed");
    const data = await res.json();
    segments = data.segments || {};
    if (!segments || Object.keys(segments).length === 0) segments = {};
    console.log("Segments loaded:", segments);
  } catch (err) {
    console.error("Segments load failed:", err);
    segments = {};
  }
}

// ---------------------------
// FETCH ALL METRICS FOR DOMAIN
// ---------------------------
async function fetchAllMetrics(domain) {
  try {
    const [
      uptime,
      latency,
      ssl,
      seo,
      vulnerabilities,
      traffic
    ] = await Promise.all([
      fetch(`${API_BASE}/uptime/${domain}`).then(r => r.json()),
      fetch(`${API_BASE}/latency/${domain}`).then(r => r.json()),
      fetch(`${API_BASE}/ssl/${domain}`).then(r => r.json()),
      fetch(`${API_BASE}/seo/${domain}`).then(r => r.json()),
      fetch(`${API_BASE}/vulnerabilities/${domain}`).then(r => r.json()),
      fetch(`${API_BASE}/traffic/${domain}`).then(r => r.json())
    ]);

    return { domain, uptime, latency, ssl, seo, vulnerabilities, traffic };
  } catch (err) {
    console.error(`Metrics fetch failed for ${domain}:`, err);
    return null;
  }
}

// ---------------------------
// RENDER CARDS
// ---------------------------
function renderGrid(resultsList) {
  if (!resultsList || resultsList.length === 0) return;

  let uptimeHTML = "";
  let latencyHTML = "";
  let sslHTML = "";
  let seoHTML = "";
  let vulnHTML = "";
  let trafficHTML = "";
  let summaryHTML = "";
  let recHTML = "";


  resultsList.forEach(r => {
    if (!r) return;
    const domain = r.domain;


    uptimeHTML += `${domain} → ${r.uptime?.status || "Unknown"}<br>`;

    latencyHTML += `${domain} → ${r.latency?.response_time_ms ?? "--"} ms<br>`;

    sslHTML += `${domain} → ${r.ssl?.valid ? "Valid" : "Invalid"}<br>`;

    seoHTML += `${domain} → ${r.seo?.score ?? "--"}<br>`;

    vulnHTML += `${domain} → ${r.vulnerabilities?.count ?? 0}<br>`;

    trafficHTML += `${domain} → ${r.traffic?.visits ?? "--"}<br>`;

    summaryHTML += `${domain}: ${r.uptime?.status === "up" ? "Operational" : "Down"}, ${r.latency?.load_time ? Math.round(r.latency.load_time * 1000) : "--"} ms<br>`;


    if ((r.vulnerabilities?.count ?? 0) > 0) recHTML += `${domain}: Patch ${r.vulnerabilities.count} vulnerabilities<br>`;

    if (!r.ssl?.valid) recHTML += `${domain}: SSL misconfiguration detected<br>`;

    if (!r.seo?.score) recHTML += `${domain}: SEO improvements recommended<br>`;
  });

  uptimeEl.innerHTML = uptimeHTML || "--";
  responseEl.innerHTML = latencyHTML || "--";
  sslEl.innerHTML = sslHTML || "--";
  seoEl.innerHTML = seoHTML || "--";
  vulnEl.innerHTML = vulnHTML || "--";
  trafficEl.innerHTML = trafficHTML || "--";
  summaryEl.innerHTML = summaryHTML || "--";
  recEl.innerHTML = recHTML || "No critical issues detected.";
}

// ---------------------------
// MONITORING LOOP (FIXED)
// ---------------------------
// ---------------------------
async function monitoringLoop() {
  if (!segments || !Object.keys(segments).length) return;

  // Gather promises for all segments
  const allPromises = Object.values(segments).flatMap(domains =>
    domains.map(fetchAllMetrics)
  );

  // Wait for all metrics to resolve
  const results = await Promise.all(allPromises);

  // Filter out null/undefined results
  const allResults = results.filter(Boolean);

  // Render the grid once
  renderGrid(allResults);
}

// ---------------------------
// ADD DOMAIN
// ---------------------------
async function addAdditionalURL() {
  const domain = normalizeDomain(addInput.value);
  if (!domain) {
    alert("Enter a valid domain");
    return;
  }

  try {
    const payload = { domain, segment: "default" };
    const res = await fetch(`${API_BASE}/add_url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) alert(data.detail || "Failed to add domain");
    console.log("Domain added:", data);

    addInput.value = "";

    // Immediate fetch for newly added domain
    const immediate = await fetchAllMetrics(domain);
    if (immediate) renderGrid([immediate]);

    // Reload all segments
    await loadDomains();
  } catch (err) {
    console.error("Add domain failed:", err);
  }
}

// ---------------------------
// INIT
// ---------------------------
async function init() {
  await loadDomains();
  monitoringLoop();
  setInterval(monitoringLoop, REFRESH_INTERVAL);

  // Attach button
  if (addButton) addButton.addEventListener("click", addAdditionalURL);
}

init();


function renderDomainsTable(domainsData) {
  const container = document.getElementById("domains-table");
  if (!container) return;

  let html = `
    <table style="width:100%; color:white;">
      <tr>
        <th>Domain</th>
        <th>Status</th>
        <th>Response</th>
        <th>SSL</th>
        <th>Vulnerabilities</th>
      </tr>
  `;

  domainsData.forEach(d => {
    html += `
      <tr>
        <td>${d.domain}</td>
        <td>${d.status}</td>
        <td>${d.response_time_ms ?? "--"} ms</td>
        <td>${d.ssl.days_remaining ?? "N/A"} days</td>
        <td>${d.vulnerabilities.total}</td>
      </tr>
    `;
  });

  html += `</table>`;

  container.innerHTML = html;
}







