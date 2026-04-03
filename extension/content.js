// Added: debounce repeated Gmail DOM updates and skip reprocessing the same email.
let analyzeTimer = null;
let lastAnalyzedSignature = "";

// This function runs whenever the page content changes (like opening a new email).
const analyzeEmail = () => {
    // Grab the email body and sender after Gmail has rendered the active message.
    const emailBody = document.querySelector('.a3s.aiL')?.innerText?.trim() || "";
    const senderEmail = document.querySelector('.gD')?.getAttribute('email') || "";

    if (!emailBody && !senderEmail) {
        return;
    }

    const currentSignature = `${senderEmail}\n${emailBody}`;
    if (currentSignature === lastAnalyzedSignature) {
        return;
    }

    lastAnalyzedSignature = currentSignature;

    let score = 0;
    let detectedTactic = "None detected";
    let description = "No obvious scam signals were found in this email.";
    let recommendation = "Safe to proceed.";

    // Simple phishing logic.
    const suspiciousKeywords = ["urgent", "bank", "verify", "password", "suspended", "click here"];
    const foundKeywords = suspiciousKeywords.filter((word) => emailBody.toLowerCase().includes(word));

    if (foundKeywords.length > 0) {
        score += foundKeywords.length * 15;
        detectedTactic = "Suspicious Language";
        description = `Found suspicious keywords: ${foundKeywords.join(", ")}.`;
        recommendation = "Do not click any links. Verify the sender's identity.";
    }

    // Impersonation check: looks for "google" in the address without the official domain.
    if (senderEmail.includes("google") && !senderEmail.endsWith("@google.com")) {
        score += 40;
        detectedTactic = "Impersonation";
        description = "The sender appears to reference Google without using an official @google.com address.";
        recommendation = "This sender is mimicking a trusted brand. Use caution.";
    }

    // Cap the score at 100.
    score = Math.min(score, 100);

    // Save the data to storage so the popup can see it.
    chrome.storage.local.set({
        riskData: {
            score,
            tactic: detectedTactic,
            description,
            recommendation
        }
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
