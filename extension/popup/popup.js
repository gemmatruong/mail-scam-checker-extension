chrome.storage.local.get(['riskData'], (result) => {
    if (result.riskData) {
        // Find the elements in popup.html and update them
        document.querySelector('.popup-container p').innerText = `Risk Score: ${result.riskData.score}/100`;
        document.querySelector('.popup-two p:first-child').innerText = `Phishing tactic: ${result.riskData.tactic}`;
        document.querySelector('.popup-three p').innerText = `Recommendation: ${result.riskData.recommendation}`;
    }
});