document.addEventListener('DOMContentLoaded', () => {
  chrome.storage.local.get(['riskData'], (result) => {
    const data = result.riskData;

    document.getElementById('risk-score').textContent =
      data ? `Risk Score: ${data.score}/100` : "No data yet";

    document.getElementById('tactic').textContent =
      data ? `Phishing tactic: ${data.tactic}` : "";

    document.getElementById('recommendation').textContent =
      data ? `Recommendation: ${data.recommendation}` : "";
  });
});