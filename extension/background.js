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

    const { emailBody, senderEmail, senderName, links } = message.payload;
    
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

    // Check for suspicious link
    // Link pointing to a raw IP address
    const IP_PATTERN = /^https?:\/\/\d{1,3}(\.\d{1,3}){3}/;
    const ipLinks    = links.filter(l => IP_PATTERN.test(l.href));

    if (ipLinks.length > 0) {
        score += 25;
        tactics.push("Suspicious Link Destination");
        descriptions.push(`A link points to a raw IP address: ${ipLinks[0].href}`);
    }

    // Shorten links
    const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "cutt.ly"];
    const shortenedLinks = links.filter(l => SHORTENERS.some(s => l.href.includes(s)));

    if (shortenedLinks.length > 0) {
        score += 15;
        tactics.push("Shortened Link");
        descriptions.push("A shortened URL was found — the real destination is hidden.");
    }

    // Visible URL text doesn't match the actual href destination.
    const mismatchedLinks = links.filter(l => {
        if (!/^https?:\/\//i.test(l.text.trim())) return false;
        try {
            return new URL(l.text.trim()).hostname !== new URL(l.href).hostname;
        } catch {
            return false;
        }
    });

    if (mismatchedLinks.length > 0) {
        score += 30;
        tactics.push("Link Mismatch");
        descriptions.push("A link's visible URL does not match its actual destination.");
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