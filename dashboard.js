// ---------------------------
// SitePulseAI Frontend Logic (Modular JS)
// ---------------------------



// dashboard.js
const API_BASE = "https://sitepulseai-demo-backend.onrender.com";



// ✅ PUT THIS AT THE TOP OF dashboard.js


async function fetchTraffic(domain) {
  try {
    const res = await fetch(`${API_BASE}/traffic/${domain}`);
    return await res.json();
  } catch (err) {
    console.error("Traffic fetch failed:", err);
    return { visitors_30d: 0, status: "Error" };
  }
}

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
  vulnerabilitiesRaw,
  traffic
] = await Promise.all([
  fetch(`${API_BASE}/uptime/${domain}`).then(r => r.json()),
  fetch(`${API_BASE}/latency/${domain}`).then(r => r.json()),
  fetch(`${API_BASE}/ssl/${domain}`).then(r => r.json()),
  fetch(`${API_BASE}/seo/${domain}`).then(r => r.json()),
  fetch(`${API_BASE}/vulnerabilities/${domain}`).then(r => r.json()),
  fetch(`${API_BASE}/traffic/${domain}`).then(r => r.json())
]);

// 🔥 flatten vulnerability response
const vulnerabilities = vulnerabilitiesRaw?.vulnerabilities;

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

    console.log("FINAL OBJECT:", r); // ✅ NOW IN SCOPE

    const domain = r.domain;


const visitors = r.traffic?.visitors_30d;
const status = r.traffic?.status;

let trafficDisplay;

if (visitors !== null && visitors !== undefined && visitors > 0) {
  trafficDisplay = `${visitors} visitors (30d)`;
} else if (status === "Beta") {
  trafficDisplay = "Beta (Data Pending)";
} else if (status === "Error") {
  trafficDisplay = "Traffic Unavailable";
} else {
  trafficDisplay = "No Traffic Data";
}

    // ---------------------------
    // UPTIME
    // ---------------------------
    uptimeHTML += `${domain} → ${r.uptime?.status || "Unknown"}<br>`;



    // ---------------------------
    // LATENCY
    // ---------------------------
    latencyHTML += `${domain} → ${r.latency?.response_time_ms ?? "--"} ms<br>`;



    // ---------------------------
    // SSL
    // ---------------------------
    const isValid = r.ssl?.valid;
    const days = r.ssl?.expires_in_days;
    const managed = r.ssl?.managed;

    if (typeof days === "number") {
      sslHTML += `${domain} → ${isValid ? "Valid" : "Invalid"} | Expires in ${days} days | Managed: ${managed ? "Yes" : "No"}<br>`;
    } else {
      sslHTML += `${domain} → SSL Unknown<br>`;
    }

    // ---------------------------
    // SEO
    // ---------------------------
    seoHTML += `${domain} → ${r.seo?.score ?? "--"}<br>`;


    // ---------------------------
    // 🔥 VULNERABILITIES (FIXED)
    // ---------------------------

    // Handle BOTH possible structures
    const vulnData =
      r.vulnerabilities?.risk_score !== undefined
        ? r.vulnerabilities
        : r.vulnerabilities?.vulnerabilities;

    if (!vulnData) {
      vulnHTML += `${domain} → Scan Failed<br>`;
    } else {
      const riskScore = vulnData.risk_score;
      const totalVulns = vulnData.total ?? 0;

      vulnHTML += `${domain} → ${riskScore}<br>`;

      if (totalVulns > 0) {
        recHTML += `${domain}: Patch ${totalVulns} vulnerabilities<br>`;
      }
    }


    // ---------------------------
    // TRAFFIC
    // ---------------------------
    trafficHTML += `${domain} → ${r.traffic?.visits ?? ""}<br>`;


    trafficHTML += `
  <div class="metric-card">
    <h3>${domain}</h3>
    <p>${trafficDisplay}</p>
  </div>
`;


    // ---------------------------
    // SUMMARY
    // ---------------------------
    summaryHTML += `${domain}: ${
      r.uptime?.status === "up" ? "Operational" : ""
    }, ${
      r.latency?.load_time
        ? Math.round(r.latency.load_time * 1000) + " ms"
        : ""
    }<br>`;


    // ---------------------------
    // RECOMMENDATIONS
    // ---------------------------
    if (!r.ssl?.valid) {
      recHTML += `${domain}: SSL misconfiguration detected<br>`;
    }

    if (!r.seo?.score) {
      recHTML += `${domain}: SEO improvements recommended<br>`;
    }
  });


  // ---------------------------
  // RENDER TO UI
  // ---------------------------
  uptimeEl.innerHTML = uptimeHTML || "--";
  responseEl.innerHTML = latencyHTML || "--";
  sslEl.innerHTML = sslHTML || "--";
  seoEl.innerHTML = seoHTML || "--";
  vulnEl.innerHTML = vulnHTML || "--";
  trafficEl.innerHTML = trafficHTML || "--";
  summaryEl.innerHTML = summaryHTML || "--";
  recEl.innerHTML = recHTML || "";
}



// ---------------------------
// MONITORING LOOP (FIXED)
// ---------------------------
async function monitoringLoop() {
  if (!segments || Object.keys(segments).length === 0) return;

  const allResults = [];

  for (const segment in segments) {
    const domains = segments[segment];
    const results = await Promise.all(domains.map(fetchAllMetrics));
    results.forEach(r => r && allResults.push(r));
  }

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





