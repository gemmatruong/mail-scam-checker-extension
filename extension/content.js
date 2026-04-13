// Added: debounce repeated Gmail DOM updates and skip reprocessing the same email.
let analyzeTimer = null;
let lastAnalyzedSignature = "";

// Clear data when no email is open. 
const clearRiskData = () => {
    lastAnalyzedSignature = "";
    chrome.storage.local.remove("riskData");
};


// This function runs whenever the page content changes (like opening a new email).
const analyzeEmail = () => {
    // Grab the email body and sender after Gmail has rendered the active message.
    const emailBody = document.querySelector('.a3s.aiL')?.innerText?.trim() || "";
    const senderEmail = document.querySelector('.gD')?.getAttribute('email') || "";
    const senderName = document.querySelector('.gD')?.getAttribute('name') || "";

    if (!emailBody && !senderEmail) {
        clearRiskData();
        return;
    }

    const currentSignature = `${senderEmail}\n${emailBody}`;
    if (currentSignature === lastAnalyzedSignature) {
        return;
    }

    lastAnalyzedSignature = currentSignature;

    // Send extracted data to background.js for analysis.
    chrome.runtime.sendMessage({
        type: "ANALYZE_EMAIL",
        payload: { emailBody, senderEmail, senderName }
    });
};

// Added: queue analysis slightly later so Gmail has time to finish rendering.
const scheduleAnalysis = (delay = 400) => {
    clearTimeout(analyzeTimer);
    analyzeTimer = setTimeout(analyzeEmail, delay);
};

// Added: Gmail updates the message view without full page reloads, so watch the DOM too.
const contentObserver = new MutationObserver(() => {
    scheduleAnalysis();
});

if (document.body) {
    contentObserver.observe(document.body, {
        childList: true,
        subtree: true
    });
}

window.addEventListener('hashchange', () => {
    scheduleAnalysis(600);
});

// Initial run after Gmail finishes painting the currently opened email.
scheduleAnalysis(1000);
