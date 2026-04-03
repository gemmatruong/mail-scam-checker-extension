// Added: centralize popup rendering so we can update both on open and on storage changes.
const renderRiskData = (data) => {
  document.getElementById('risk-score').textContent =
    data ? `Risk Score: ${data.score}/100` : "Risk Score: --";

  document.getElementById('tactic').textContent =
    data ? `Phishing tactic: ${data.tactic}` : "Phishing tactic: Not analyzed yet";

  document.getElementById('description').textContent =
    data ? `Details: ${data.description}` : "Open an email in Gmail to analyze it.";

  document.getElementById('recommendation').textContent =
    data ? `Recommendation: ${data.recommendation}` : "";
};

document.addEventListener('DOMContentLoaded', () => {
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
