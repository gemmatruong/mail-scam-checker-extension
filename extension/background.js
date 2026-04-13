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

    const { emailBody, senderEmail, senderName } = message.payload;
    
    // Avoid case-sensitivity
    const bodyLower  = emailBody.toLowerCase();
    const emailLower = senderEmail.toLowerCase();
    const nameLower  = senderName.toLowerCase();

    let score = 0;
    const tactics      = [];
    const descriptions = [];

    // Suspicious languages: check for suspicious keywords in email body
    const foundKeywords = SUSPICIOUS_KEYWORDS.filter((word) => bodyLower.includes(word));

    if (foundKeywords.length > 0) {
        score += Math.min(foundKeywords.length * 10, 40);
        tactics.push("Suspicious Language");
        descriptions.push(`Found ${foundKeywords.length} suspicious keyword(s): ${foundKeywords.join(", ")}.`);
    }

    // Impersonation check: looks for brand name in the address without the official domain.
    for (const [brand, officialDomain] of Object.entries(KNOWN_BRANDS)) {
        if (nameLower.includes(brand) && !emailLower.endsWith(`@${officialDomain}`))
        {
            score += 40;
            tactics.push("Brand Impersonation");
            descriptions.push(`Sender claims to be "${brand}" but is not from @${officialDomain}.`)
        }
    }

    // Cap the score at 100.
    score = Math.min(score, 100);

    let recommendation;
    if (score < 30)       recommendation = "No major warning signs detected, but stay alert.";
    else if (score < 65)  recommendation = "Be cautious. Double-check the sender and inspect links before taking action.";
    else                  recommendation = "Do not click links or open attachments. Verify the sender independently.";

    const detectedTactic = tactics.length      > 0 ? tactics.join(", ")      : "None detected";
    const description    = descriptions.length > 0 ? descriptions.join(" ")  : "No obvious scam signals were found in this email.";

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