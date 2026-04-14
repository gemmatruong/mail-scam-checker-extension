/**
 * popup.js
 * Renders the popup view for the most recent Gmail analysis.
 *
 * The popup reads `riskData` from extension storage when it opens and also
 * listens for storage updates so the UI refreshes if a new email is analyzed
 * while the popup is already visible.
 */


const renderRiskData = (data) => {
  const hasData = Boolean(data);

  document.getElementById('risk-score').textContent =
    hasData ? `Risk Score: ${data.score}/100` : 'Risk Score: --';

  // Show a bullet-style list when multiple tactics were detected.
  const tacticEl = document.getElementById('tactic');
  if (hasData && data.tactic !== 'None detected') {
    tacticEl.innerHTML =
      'Phishing tactic(s):<br>' +
      data.tactic.split(', ').map((tactic) => `&bull; ${tactic}`).join('<br>');
  } else {
    tacticEl.textContent = hasData
      ? 'Phishing tactic: None detected'
      : 'Phishing tactic: Not analyzed yet';
  }

  document.getElementById('recommendation').textContent =
    hasData ? `Recommendation: ${data.recommendation}` : '';
};

document.addEventListener('DOMContentLoaded', () => {
  // Load whatever result is already stored when the popup opens.
  chrome.storage.local.get(['riskData'], (result) => {
    renderRiskData(result.riskData);
  });

  // Keep the popup in sync if a new Gmail message is analyzed live.
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName !== 'local' || !changes.riskData) {
      return;
    }

    renderRiskData(changes.riskData.newValue);
  });
});
