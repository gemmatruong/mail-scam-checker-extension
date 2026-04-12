# Simple Phishing Logic

## 1. Sender check
#### Rule 1.1: Brand name mismatch
If the sender name includes a known brand but the sender email domain is not official.

Example:

- sender name: `Google Support`
- sender email: `alerts@google-help-login.net`

Warning: possible impersonation

Suggested score: `+40`



#### Rule 1.2: Free email pretending to be a company
If the sender claims to be a company or support team but uses:

- `gmail.com`
- `yahoo.com`
- `outlook.com`

Example:

- `PayPal Billing <paypal-helpdesk@gmail.com>`

Warning: possible spoofing

Suggested score: `+20`


#### Rule 1.3: Suspicious sender words
If sender name or sender email includes words like:

- support
- billing
- security
- verify
- account

and looks unusual or unofficial.

Suggested score: `+15`


## 2. Body text check
#### Rule 2.1: Urgent language
Examples:

- urgent
- act now
- immediate action required
- final notice
- suspended
- verify now

Suggested score: `+15`

Warning: urgent language detected


#### Rule 2.2: Credential request
Examples:

- verify your account
- confirm your password
- login now
- reset your password
- reauthenticate

Suggested score: `+25`

Warning: credential request detected


#### Rule 2.3: Financial pressure
Examples:

- invoice
- refund
- payment failed
- wire transfer
- billing issue

Suggested score: `+20`

Warning: financial pressure detected


#### Rule 2.4: Threat language
Examples:

- account suspended
- terminated
- legal action
- security alert
- unauthorized login

Suggested score: `+15`

Warning: threat language detected


## 3. Link check

#### Rule 3.1: Link points to raw IP address
Example:

- `http://185.44.20.9/login`

Suggested score: `+25`

Warning: suspicious link destination


#### Rule 3.2: Shortened URL
Examples:

- bit.ly
- tinyurl.com
- t.co
- cutt.ly

Suggested score: `+15`

Warning: shortened link detected


#### Rule 3.3: Brand-looking text but suspicious destination
Example:

- link text: `Google Security`
- href: `https://google-login-help.xyz`

Suggested score: `+30`

Warning: misleading link


#### Rule 3.4: Visible URL does not match actual destination
Example:

- visible text: `https://google.com`
- actual href: `https://fake-login.example`

Suggested score: `+30`

Warning: link mismatch detected


---

## Risk levels

Three levels:

- `0-29` -> **Low Risk** -> deflated pufferfish
- `30-64` -> **Medium Risk** -> slightly pufferfish
- `65-100` -> **High Risk** -> BLOWN INFLATED HUGE PUFFERFISH


---

## Recommendation logic

### Low Risk
`No major warning signs detected, but stay alert.`

### Medium Risk
`Be cautious. Double-check the sender and inspect links before taking action.`

### High Risk
`Do not click links or open attachments. Verify the sender independently.`

