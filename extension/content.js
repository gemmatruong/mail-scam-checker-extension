// Known brands used for a basic impersonation check.
const KNOWN_BRANDS = {
    google: 'google.com',
    paypal: 'paypal.com',
    apple: 'apple.com',
    microsoft: 'microsoft.com',
    amazon: 'amazon.com',
    facebook: 'facebook.com',
    netflix: 'netflix.com',
    instagram: 'instagram.com',
    twitter: 'twitter.com',
    linkedin: 'linkedin.com',
    dropbox: 'dropbox.com',
    chase: 'chase.com',
};

// Keywords and phrases that often appear in phishing or scam messages.
const SUSPICIOUS_KEYWORDS = [
    'urgent',
    'act now',
    'immediate action required',
    'final notice',
    'suspended',
    'verify now',
    'verify your account',
    'confirm your password',
    'login now',
    'reset your password',
    'reauthenticate',
    'invoice',
    'refund',
    'payment failed',
    'wire transfer',
    'billing issue',
    'account suspended',
    'terminated',
    'legal action',
    'security alert',
    'unauthorized login',
];

// Shortened URLs and raw IP destinations often hide where a link really goes.
const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'cutt.ly'];

// These two values help us debounce Gmail re-renders and skip duplicate scans.
let analyzeTimer = null;
let lastAnalyzedSignature = '';

// Convert the extracted message into a simple 0-100 phishing risk summary.
const scoreEmail = ({ emailBody, senderEmail, senderName, links }) => {
    const bodyLower = emailBody.toLowerCase();
    const emailLower = senderEmail.toLowerCase();
    const nameLower = senderName.toLowerCase();

    let score = 0;
    const tactics = [];

    // Check for common phishing keywords in the email body.
    const foundKeywords = SUSPICIOUS_KEYWORDS.filter((word) => bodyLower.includes(word));
    if (foundKeywords.length > 0) {
        score += Math.min(foundKeywords.length * 10, 30);
        tactics.push('Suspicious Language');
    }

    // Check if the sender name contains a known brand but the email domain does not match.
    for (const [brand, officialDomain] of Object.entries(KNOWN_BRANDS)) {
        if (nameLower.includes(brand) && !emailLower.endsWith(`@${officialDomain}`)) {
            score += 30;
            tactics.push('Brand Impersonation');
        }
    }

    // Check for links that use known URL shorteners, which can hide the true destination.
    const shortenedLinks = links.filter((link) =>
        SHORTENERS.some((shortener) => link.href.includes(shortener))
    );
    if (shortenedLinks.length > 0) {
        score += 15;
        tactics.push('Shortened Link');
    }

    // Flag links whose visible text points to one domain but actually opens another.
    const mismatchedLinks = links.filter((link) => {
        if (!/^https?:\/\//i.test(link.text.trim())) {
            return false;
        }

        try {
            return new URL(link.text.trim()).hostname !== new URL(link.href).hostname;
        } catch {
            return false;
        }
    });

    if (mismatchedLinks.length > 0) {
        score += 30;
        tactics.push('Link Mismatch');
    }

    // Keep the score in the same range expected by the popup UI.
    score = Math.min(score, 100);

    let recommendation;
    if (score < 30) {
        recommendation = 'No major warning signs detected, but stay alert.';
    } else if (score < 65) {
        recommendation =
            'Be cautious! Double-check the sender and inspect links before taking action.';
    } else {
        recommendation =
            'Alert! Do not click links or open attachments. Verify the sender independently.';
    }

    return {
        score,
        tactic: tactics.length > 0 ? tactics.join(', ') : 'None detected',
        recommendation,
    };
};

// This function runs whenever the page content changes, like when Gmail opens a new email.
const analyzeEmail = () => {
    const emailBody = document.querySelector('.a3s.aiL')?.innerText?.trim() || '';
    const senderEmail = document.querySelector('.gD')?.getAttribute('email') || '';
    const senderName = document.querySelector('.gD')?.getAttribute('name') || '';

    // If Gmail has not finished rendering the open message yet, wait for the next pass.
    if (!emailBody && !senderEmail) {
        return;
    }

    // Use sender + body text as a cheap fingerprint for the currently open email.
    const currentSignature = `${senderEmail}\n${emailBody}`;
    if (currentSignature === lastAnalyzedSignature) {
        return;
    }

    lastAnalyzedSignature = currentSignature;

    const linkElements = document.querySelectorAll('.a3s.aiL a');
    const links = Array.from(linkElements)
        .map((anchor) => ({
            text: anchor.innerText?.trim() || '',
            href: anchor.href || '',
        }))
        .filter((link) => link.href.startsWith('http'));

    // Store the latest result so the popup can render it immediately.
    const riskData = scoreEmail({ emailBody, senderEmail, senderName, links });
    chrome.storage.local.set({ riskData });
};

// Gmail mutates the DOM heavily, so we delay scans until the UI settles a bit.
const scheduleAnalysis = (delay = 400) => {
    clearTimeout(analyzeTimer);
    analyzeTimer = setTimeout(analyzeEmail, delay);
};

// Watch for in-page Gmail navigation and message swaps without a full reload.
const contentObserver = new MutationObserver(() => {
    scheduleAnalysis();
});

if (document.body) {
    contentObserver.observe(document.body, {
        childList: true,
        subtree: true,
    });
}

window.addEventListener('hashchange', () => {
    scheduleAnalysis(600);
});

// Run once on initial load after Gmail has had time to paint the message view.
scheduleAnalysis(1000);
