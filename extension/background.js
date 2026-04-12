const KNOWN_BRANDS = {
    "google":        "google.com",
    "paypal":        "paypal.com",
    "apple":         "apple.com",
    "microsoft":     "microsoft.com",
    "amazon":        "amazon.com",
    "facebook":      "facebook.com",
    "netflix":       "netflix.com",
    "instagram":     "instagram.com",
    "twitter":       "twitter.com",
    "linkedin":      "linkedin.com",
    "dropbox":       "dropbox.com",
    "chase":         "chase.com",
};


const SUSPICIOUS_KEYWORDS = [
    // Urgent language
    "urgent", "act now", "immediate action required", "final notice", "suspended", "verify now",
    // Credential requests
    "verify your account", "confirm your password", "login now", "reset your password", "reauthenticate",
    // Financial pressure
    "invoice", "refund", "payment failed", "wire transfer", "billing issue",
    // Threat language
    "account suspended", "terminated", "legal action", "security alert", "unauthorized login",
];


// Listens for extracted email data sent by content.js.
chrome.runtime.onMessage.addListener((message) => {
    if (message.type !== "ANALYZE_EMAIL") {
        return;
    }

    const { emailBody, senderEmail } = message.payload;

    let score = 0;
    let detectedTactic = "None detected";
    let description = "No obvious scam signals were found in this email.";
    let recommendation = "Safe to proceed.";

    // Simple phishing logic.
    const foundKeywords = SUSPICIOUS_KEYWORDS.filter((word) => emailBody.toLowerCase().includes(word));

    if (foundKeywords.length > 0) {
        const keywordScore = Math.min(foundKeywords.length * 10, 40);
        score += keywordScore;
        detectedTactic = "Suspicious Language";
        description = `Found ${foundKeywords.length} suspicious keyword(s): ${foundKeywords.join(", ")}.`;
    }

    // Impersonation check: looks for "google" in the address without the official domain.
    if (senderEmail.includes("google") && !senderEmail.endsWith("@google.com")) {
        score += 40;
        detectedTactic = "Impersonation";
        description = "The sender appears to reference Google without using an official @google.com address.";
    }

    // Cap the score at 100.
    score = Math.min(score, 100);

    // Recommendations based on risk scores
    if (score < 30) {
        recommendation = "No major warning signs detected, but stay alert.";
    } else if (score < 65) {
        recommendation = "Medium Risk! Be cautious. Double-check the sender and inspect links before taking action.";
    } else {
        recommendation = "High Risk!!! Do not click links or open attachments. Verify the sender independently.";
    }

    // Save the data to storage so the popup can see it.
    chrome.storage.local.set({
        riskData: {
            score,
            tactic: detectedTactic,
            description,
            recommendation
        }
    });
});