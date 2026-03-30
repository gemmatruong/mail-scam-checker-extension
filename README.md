# Mail Scam Checker (Chrome Extension)

A Chrome extension that helps detect potential email scams by analyzing patterns commonly found in phishing and scam messages.
This group project includes creating a Google Chrome Extension to read various emails, check whether they are suspicious or not, then give the user warning messages depending on how dangerous the email is. Our program will be able to check files and common mistakes in dangerous emails used to steal users information or for hacking. This will help users recognize phishing and scams by relaying either a low, medium, or high warning level.

# How It Works
  The extension will immediately search for frequent risk factors found in emails once they are opened. This includes searching for suspicious links, urging and/or convincing language, unknown senders, and
requestions for personal and sensitive information. Based on how dangerous the links or messages may be, a risk warning with levels low, medium, or high, will immediately pop-up for the user. If the email
is safe, a safe pop-up will appear.

# Privacy Statement
  # Data Accessed
    The data that will be accessed will only contain content within emails recieved, sender information, as well as outside links sent to the user. 
  # Stored Content
    We will not store, transmit, or sell any user data and all evaluations of emails will be in the local browser currently being used. 
  # Why We Need Permissions
    We must use these permissions in order to fully scan recieved emails to determine it's safetly level as well as to support the browser that the user utilizes.

# Permissions Used
  The permissions used will include the active Gmail tab, scripting to detect information on the users page, and various host_permissions such as specific email platforms like Gmail. We follow the Least 
Privilege Principle layout, using permissions that is absolutely neccessary. No background data or full browsing history would ever be requested. 

# Warning Messages
  The warning message for low will include a blue pop-up box with a calm but informative tone which would state whether a link, sender information, or tone of the email sounds unsure. It would say something like,
"This email may not be safe, be sure to verify (link, tone, sender) before continuing."
  The warning message for medium will include a yellow pop-up box with a more serious, and more urgent tone and would state something like, "This email demonstrates numerous signs of suspicion. Avoid clicking
  links from this email, sharing any personal information, and always check the sender."
  The warning message for high will include a red pop-up box with a direct and urgent tone that would state, "Warning: This email appears to be highly unsafe, do not click any links or respond to this email, 
  please condier deleting this email and reporting it."

# Future Improvements
  Future improvents could include using AI to be able to further detect malicious content on emails to keep users safe. We could also collect user feedback, and create this extension so that it works for other
email websites like Outlook.

## Features
- Scan allowed emails for suspicious content and patterns
- Calculate risk score based on email content
- Display warnings for potentially dangerous emails

## Tech
- Chrome Extension Manifest V3
- JavaScript/HTML/CSS

## Getting Started (Local Dev)

### 1) Clone
```bash
git clone https://github.com/gemmatruong/mail-scam-checker-extension.git
cd mail-scam-checker-extension