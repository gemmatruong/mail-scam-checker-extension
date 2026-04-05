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
});