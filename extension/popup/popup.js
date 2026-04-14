let detailsExpanded = false;
let detailsToggle;
let detailsPanel;

const syncDetailsView = (hasData) => {
  detailsPanel.classList.toggle('hidden', !detailsExpanded);
  detailsToggle.disabled = !hasData;
};

// Added: centralize popup rendering so we can update both on open and on storage changes.
const renderRiskData = (data) => {
  const hasData = Boolean(data);

  document.getElementById('risk-score').textContent =
    hasData ? `Risk Score: ${data.score}/100` : "Risk Score: --";

  const tacticEl = document.getElementById('tactic');
  if (hasData && data.tactic !== "None detected") {
    tacticEl.innerHTML = "Phishing tactic(s):<br>" +
      data.tactic.split(", ").map(t => `• ${t}`).join("<br>");
  } else {
    tacticEl.textContent = hasData ? "Phishing tactic: None detected" : "Phishing tactic: Not analyzed yet";
  }

  const descEl = document.getElementById('description');
  if (hasData && data.description !== "No obvious scam signals were found in this email.") {
    const bullets = data.description
      .split(/(?<=\.)\s+/)
      .filter(s => s.trim());
    descEl.innerHTML = bullets.map(b => `<li>${b}</li>`).join("");
  } else {
    descEl.innerHTML = `<li>${hasData ? "No obvious scam signals were found." : "Open an email in Gmail to analyze it."}</li>`;
  }

  document.getElementById('recommendation').textContent =
    hasData ? `Recommendation: ${data.recommendation}` : "";

  if (!hasData) {
    detailsExpanded = false;
  }

  syncDetailsView(hasData);
};

document.addEventListener('DOMContentLoaded', () => {
  detailsToggle = document.getElementById('details-toggle');
  detailsPanel = document.getElementById('details-panel');

  detailsToggle.addEventListener('click', () => {
    if (detailsToggle.disabled) {
      return;
    }

    detailsExpanded = !detailsExpanded;
    syncDetailsView(true);
  });

  chrome.storage.local.get(['riskData'], (result) => {
    renderRiskData(result.riskData);
  });

  // Added: refresh the popup immediately when content.js writes a new score.
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName !== 'local' || !changes.riskData) {
      return;
    }

    renderRiskData(changes.riskData.newValue);
  });
});
