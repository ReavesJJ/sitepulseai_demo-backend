// ---------------------------
// Backend URL
const BACKEND_URL = "http://localhost:8000/vulnerabilities";

// Fetch vulnerability metrics for a single domain
async function fetchVulnerabilityMetrics(domain) {
  try {
    const response = await fetch(`${BACKEND_URL}/${domain}`);
    if (!response.ok) throw new Error("Network response was not ok");

    const data = await response.json();
    return {
      domain: data.domain,
      findings: data.findings || [],
      counts: data.counts || { critical: 0, high: 0, medium: 0, low: 0 },
      risk_score: data.risk_score || 0
    };
  } catch (err) {
    console.error(`Failed to fetch metrics for ${domain}:`, err);
    return null;
  }
}

// Update or inject risk score and counts into a card
function updateVulnCard(result) {
  // Select the card by domain, fallback to first card if IDs aren't set
  const card = document.querySelector(`#card-${result.domain}`) || document.querySelector(".vuln-card");
  if (!card) return;

  // Risk score
  let riskElem = card.querySelector(".risk-score");
  if (!riskElem) {
    riskElem = document.createElement("div");
    riskElem.className = "risk-score";
    riskElem.style.fontWeight = "bold"; // optional styling
    card.appendChild(riskElem);
  }
  riskElem.textContent = `Risk Score: ${result.risk_score}`;

  // Severity counts
  let countsElem = card.querySelector(".severity-counts");
  if (!countsElem) {
    countsElem = document.createElement("div");
    countsElem.className = "severity-counts";
    card.appendChild(countsElem);
  }
  countsElem.textContent = `C:${result.counts.critical} H:${result.counts.high} M:${result.counts.medium} L:${result.counts.low}`;
}

// ---------------------------
// Monitoring loop integration
async function monitoringLoop() {
  if (!segments || !Object.keys(segments).length) return;

  // Flatten all domain promises
  const allPromises = Object.values(segments).flatMap(domains =>
    domains.map(fetchVulnerabilityMetrics)
  );

  const results = await Promise.all(allPromises);
  const allResults = results.filter(Boolean);

  // Render your existing grid as usual
  renderGrid(allResults);

  // Inject real-time risk scores into cards
  allResults.forEach(updateVulnCard);
}

// ---------------------------
// Optional: auto-refresh every X seconds
setInterval(monitoringLoop, 30000); // refresh every 30s