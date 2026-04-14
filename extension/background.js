/**
 * background.js
 * Service worker for the extension.
 *
 * Receives normalized email data from `content.js`, scores the message for
 * common phishing signals, and stores the result in `chrome.storage.local`
 * so the popup can render the latest analysis.
 */

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

chrome.runtime.onMessage.addListener((message) => {
  if (message.type !== 'ANALYZE_EMAIL') {
    return;
  }

  const { emailBody, senderEmail, senderName, links } = message.payload;

  const bodyLower = emailBody.toLowerCase();
  const emailLower = senderEmail.toLowerCase();
  const nameLower = senderName.toLowerCase();

  let score = 0;
  const tactics = [];

  // Suspicious wording increases the score, capped so one long email does not dominate.
  const foundKeywords = SUSPICIOUS_KEYWORDS.filter((word) => bodyLower.includes(word));
  if (foundKeywords.length > 0) {
    score += Math.min(foundKeywords.length * 10, 40);
    tactics.push('Suspicious Language');
  }

  // Flag messages that name a well-known brand but do not come from its domain.
  for (const [brand, officialDomain] of Object.entries(KNOWN_BRANDS)) {
    if (nameLower.includes(brand) && !emailLower.endsWith(`@${officialDomain}`)) {
      score += 40;
      tactics.push('Brand Impersonation');
    }
  }

  // Links that use raw IPs can hide the real host and are often risky.
  const IP_PATTERN = /^https?:\/\/\d{1,3}(\.\d{1,3}){3}/;
  const ipLinks = links.filter((link) => IP_PATTERN.test(link.href));
  if (ipLinks.length > 0) {
    score += 25;
    tactics.push('Suspicious Link Destination');
  }

  // URL shorteners obscure the final destination, which raises suspicion.
  const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'cutt.ly'];
  const shortenedLinks = links.filter((link) =>
    SHORTENERS.some((shortener) => link.href.includes(shortener))
  );
  if (shortenedLinks.length > 0) {
    score += 15;
    tactics.push('Shortened Link');
  }

  // If link text shows one hostname but sends users somewhere else, flag it.
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

  // Keep the score on a simple 0-100 scale for the popup.
  score = Math.min(score, 100);

  // Convert the numeric score into an action-oriented recommendation.
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

  const detectedTactic = tactics.length > 0 ? tactics.join(', ') : 'None detected';

  // Persist the latest scan so the popup can read it immediately.
  chrome.storage.local.set({
    riskData: {
      score,
      tactic: detectedTactic,
      recommendation,
    },
  });
});
