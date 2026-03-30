// This function runs whenever the page content changes (like opening a new email)
const analyzeEmail = () => {
    //  Grab the email body and sender
    const emailBody = document.querySelector('.a3s.aiL')?.innerText || "";
    const senderEmail = document.querySelector('.gD')?.getAttribute('email') || "";

    let score = 0;
    let detectedTactic = "None detected";
    let recommendation = "Safe to proceed.";

    // Simple Phishing Logic
    const suspiciousKeywords = ["urgent", "bank", "verify", "password", "suspended", "click here"];
    const foundKeywords = suspiciousKeywords.filter(word => emailBody.toLowerCase().includes(word));

    if (foundKeywords.length > 0) {
        score += (foundKeywords.length * 15);
        detectedTactic = "Suspicious Language";
        recommendation = "Do not click any links. Verify the sender's identity.";
    }

    // Impersonation Check (Example: checks if 'google' is in the name but not the domain)
    if (senderEmail.includes("google") && !senderEmail.endsWith("@google.com")) {
        score += 40;
        detectedTactic = "Impersonation";
        recommendation = "This sender is mimicking a trusted brand. Use caution.";
    }

    // Cap the score at 100
    score = Math.min(score, 100);

    // Save the data to storage so the popup can see it
    chrome.storage.local.set({
        riskData: {
            score: score,
            tactic: detectedTactic,
            recommendation: recommendation
        }
    });
};

// Listen for clicks or URL changes to re-run the analysis when an email is opened
window.addEventListener('hashchange', () => {
    // Wait a moment for Gmail to render the email content
    setTimeout(analyzeEmail, 1000);
});

// Initial run
analyzeEmail();