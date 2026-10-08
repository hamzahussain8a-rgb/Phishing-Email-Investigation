# Phishing Email Investigation & Analysis Tool

A Python-based phishing email investigation and triage tool designed to automate common **SOC analyst email-analysis tasks**, including email header analysis, IOC extraction, URL inspection, HTML/body analysis, attachment hashing, and basic risk scoring.

The project is designed as a practical cybersecurity portfolio project demonstrating skills relevant to **SOC Analyst, Cybersecurity Analyst, Incident Response, and Threat Intelligence** roles.

---

## Project Overview

Phishing emails are a common initial access technique used by attackers to steal credentials, deliver malware, or redirect users to malicious infrastructure.

This project provides a local analysis workflow for `.eml` files and automatically extracts and analyzes indicators that a SOC analyst would typically investigate during an initial phishing alert.

### Investigation Workflow

```text
                    Phishing Email
                          │
                          ▼
                 ┌─────────────────┐
                 │  Email Parsing  │
                 └────────┬────────┘
                          │
          ┌───────────────┼────────────────┐
          ▼               ▼                ▼
     Header Analysis   URL Analysis    Body Analysis
          │               │                │
          ▼               ▼                ▼
      Sender/IPs       Domains/URLs    HTML/Keywords
          │               │                │
          └───────────────┼────────────────┘
                          ▼
                 IOC Consolidation
                          │
                          ▼
                 Attachment Analysis
                          │
                          ▼
                    Risk Scoring
                          │
                          ▼
                 Investigation Report
```

---

## Features

### Email Parsing

* Parses `.eml` files using Python's standard email library
* Supports single-part and multipart messages
* Extracts common email headers
* Identifies email content type
* Extracts email body content

### Header Analysis

Extracts:

* Sender
* Recipient
* Subject
* Date
* Return-Path when available
* `Received` headers

Received headers are further analyzed to identify IP addresses involved in the email delivery path.

### IP Address Analysis

Extracts IPv4 addresses from `Received` headers and classifies them as:

* Public
* Private
* Loopback

This helps distinguish potentially externally routable infrastructure from internal mail-processing addresses.

### Domain Extraction

Automatically extracts domain names from:

* Email headers
* Received headers
* Sender information

Duplicate domains are removed from the final IOC list.

### URL Analysis

The analyzer extracts HTTP/HTTPS URLs from email content and identifies:

* URL scheme
* Domain
* Path
* Query parameters
* Embedded URLs
* Potential redirect destinations

Example:

```text
https://www.google.com/url?q=http://example.com/login
```

The analyzer can identify the embedded destination:

```text
http://example.com/login
```

### Sender Analysis

The tool parses the sender into:

* Display name
* Email address
* Sender domain

It also checks for potential **display-name/domain mismatches**.

Example:

```text
Display Name:
Microsoft Security Team

Actual Sender:
attacker@example.com
```

This can indicate impersonation or masquerading.

### Subject Analysis

The tool:

* Decodes MIME-encoded subjects
* Normalizes the subject for analysis
* Detects suspicious keywords

Examples include:

```text
warning
urgent
verify
final notice
suspended
password
account
security alert
action required
```

### HTML Email Analysis

HTML emails are parsed using Python's `HTMLParser`.

The analyzer can identify:

* Visible text
* HTML tags
* Forms
* Password input fields
* Hidden input fields
* JavaScript
* HTML links

This can help identify phishing emails designed to collect credentials.

### Body Keyword Analysis

The visible email content is analyzed for suspicious phishing-related language such as:

```text
verify
failed
retrieve
confirm
password
account
login
suspended
urgent
click
update
validate
security
immediately
```

### Attachment Analysis

Attachments are identified and analyzed for:

* Filename
* Content type
* File size
* SHA-256 hash

The hashes can subsequently be submitted to external threat-intelligence platforms for enrichment.

### IOC Consolidation

The tool consolidates extracted indicators into categories:

```text
IPs
Domains
URLs
File Hashes
```

This provides a structured IOC set suitable for further investigation.

### Risk Scoring

A basic rule-based scoring system evaluates multiple indicators and produces:

* Risk score
* Risk classification
* Reasons contributing to the score

Example:

```text
Score: 85/100
Verdict: HIGH RISK
```

The scoring considers indicators such as:

* Sender/domain mismatch
* Suspicious subject keywords
* Suspicious body language
* Forms
* Password inputs
* Hidden inputs
* JavaScript
* URLs
* Embedded URLs
* Attachments

---

## Technologies Used

| Technology     | Purpose                             |
| -------------- | ----------------------------------- |
| Python         | Core implementation                 |
| `email`        | `.eml` parsing                      |
| `HTMLParser`   | HTML email analysis                 |
| `re`           | Pattern matching and IOC extraction |
| `ipaddress`    | IP classification                   |
| `urllib.parse` | URL parsing                         |
| `hashlib`      | SHA-256 hashing                     |
| JSON           | Investigation report output         |
| Git            | Version control                     |
| GitHub         | Source control and portfolio        |

---

## Project Structure

```text
Phishing-Email-Investigation/
│
├── investigations/
│   └── Investigation reports
│
├── screenshots/
│   └── Investigation screenshots
│
├── samples/
│   └── Local .eml samples
│
├── phishing_analyzer.py
│
├── .gitignore
│
└── README.md
```

> Phishing email samples are intentionally excluded from the public repository because `.eml` files may contain potentially sensitive or unsafe content.

---

## Installation

### Requirements

* Python 3.10+
* Git
* Windows, Linux, or macOS

The analyzer uses Python standard-library modules, so no external Python packages are required.

### Clone the Repository

```bash
git clone https://github.com/hamzahussain8a-rgb/Phishing-Email-Investigation.git
```

```bash
cd Phishing-Email-Investigation
```

---

## Usage

Place an `.eml` sample inside the local `samples` directory.

Example:

```text
samples/
└── 2020-05-05-phishing-email-example-01.eml
```

Run the analyzer:

```bash
python phishing_analyzer.py samples/2020-05-05-phishing-email-example-01.eml
```

The analyzer prints an investigation summary to the terminal and generates a JSON investigation report.

Example output:

```text
============================================================
PHISHING EMAIL INVESTIGATION
============================================================

File: 2020-05-05-phishing-email-example-01.eml

Sender:
  sues@nnwifi.com

Subject:
  Warning: Final notice : malware-traffic-analysis.net™

Suspicious Subject Keywords:
  ['warning', 'final notice']

Suspicious Body Keywords:
  ['verify', 'failed', 'retrieve']

Public IPs:
  ['173.46.174.49', '94.100.31.27']

Risk Assessment:
  Score: XX/100
  Verdict: HIGH RISK

============================================================
```

---

## Example Investigation

The project was tested against a publicly available phishing email sample from the **Malware-Traffic-Analysis** training dataset.

### Sender Analysis

The sample used a display name resembling a legitimate support organization:

```text
malware-traffic-analysis.net Support
```

while the actual sender address was:

```text
sues@nnwifi.com
```

This creates a significant display-name/domain mismatch.

### Subject

After MIME decoding, the subject contained language such as:

```text
Warning
Final notice
```

These are common urgency-based phishing indicators.

### Network Indicators

The email contained externally routable IP addresses including:

```text
173.46.174.49
94.100.31.27
```

### URLs

The email contained a link to:

```text
servervirto.com.co
```

and an additional embedded destination:

```text
em.osanewsletter.com
```

The analyzer identifies the relationship between the outer URL and embedded URL.

### Body Analysis

The HTML body contained phishing-oriented language including:

```text
You have (3) failed email deliveries
Verify your information
Retrieve your mails
```

These indicators suggest an attempt to create urgency and convince the recipient to interact with the email.

### Preliminary Assessment

The sample demonstrates multiple correlated phishing indicators:

* Sender impersonation
* Domain mismatch
* Urgency-based subject
* Suspicious body language
* External URLs
* Embedded URL
* Credential-oriented messaging

These indicators collectively support a **high-confidence phishing classification**.

---

## IOC Investigation Workflow

The analyzer is intended to support, rather than replace, analyst investigation.

After extracting IOCs, an analyst can perform additional enrichment using services such as:

* VirusTotal
* URLScan
* WHOIS/DNS investigation
* AbuseIPDB
* PhishTank
* CyberChef
* Sandbox environments

Example workflow:

```text
Email
  │
  ├── Sender
  │
  ├── IP Address ──────► Threat Intelligence
  │
  ├── Domain ──────────► DNS / WHOIS / Reputation
  │
  ├── URL ─────────────► URLScan / Reputation
  │
  └── File Hash ───────► Malware Reputation
```

External enrichment should always be performed carefully and in accordance with organizational security procedures.

---

## MITRE ATT&CK Mapping

The investigation workflow demonstrates techniques commonly associated with phishing activity.

| Technique                      | ID        | Relevance                                              |
| ------------------------------ | --------- | ------------------------------------------------------ |
| Phishing: Spearphishing Link   | T1566.002 | Malicious links delivered through email                |
| Masquerading                   | T1036     | Impersonation through sender/display-name manipulation |
| User Execution: Malicious Link | T1204.001 | User interaction with a malicious link                 |

---

## SOC Analyst Skills Demonstrated

This project demonstrates practical skills in:

* Phishing email triage
* Email header analysis
* IOC extraction
* IP address analysis
* Domain analysis
* URL analysis
* HTML inspection
* Email body analysis
* Attachment hashing
* SHA-256
* Threat intelligence workflow
* Detection logic
* Risk scoring
* Incident documentation
* JSON-based investigation output
* Python scripting
* Git/GitHub version control

---

## Security Considerations

Phishing samples should be handled carefully.

### Do not:

* Open unknown attachments
* Click links from suspicious emails
* Execute suspicious files
* Detonate malware on a normal personal machine
* Upload sensitive corporate emails to public threat-intelligence platforms

### Recommended practice

Use:

* Isolated virtual machines
* Sandboxed environments
* Safe training datasets
* Sanitized email samples
* Offline analysis where possible

The `.gitignore` configuration intentionally excludes `.eml` files from the public Git repository.

---

## Limitations

This project is intended for **initial phishing triage**, not full enterprise-grade detection.

Current limitations include:

* No live VirusTotal API integration
* No automated URLScan enrichment
* No DNS reputation integration
* No SPF/DKIM/DMARC validation when authentication results are unavailable
* Rule-based rather than machine-learning risk scoring
* Limited advanced HTML obfuscation detection
* No automatic malware sandboxing
* No enterprise SIEM integration
* No real-time email ingestion

These limitations provide opportunities for future development.

---

## Future Improvements

Potential enhancements include:

### Threat Intelligence APIs

Integrate APIs for automated:

* VirusTotal reputation checks
* URLScan searches
* AbuseIPDB IP reputation
* WHOIS information
* DNS resolution

### Authentication Analysis

Add parsing for:

```text
Authentication-Results
Received-SPF
DKIM-Signature
DMARC
```

and correlate authentication results with sender information.

### Advanced URL Detection

Add detection for:

* URL shorteners
* Punycode domains
* Lookalike domains
* IP-based URLs
* Excessive redirects
* Suspicious TLDs
* URL encoding/obfuscation

### Better Risk Scoring

Move from simple rule-based scoring toward a weighted detection model based on:

```text
Sender reputation
+
Authentication results
+
URL reputation
+
Domain age
+
HTML indicators
+
Attachment reputation
+
Threat intelligence
```

### SOC Integration

Potential future integration with:

* Wazuh
* Splunk
* Microsoft Sentinel
* TheHive
* Cortex
* SIEM/SOAR platforms

---

## Learning Objectives

This project was developed to gain practical experience with the workflow used during phishing investigations:

```text
Triage
  ↓
Extract
  ↓
Analyze
  ↓
Enrich
  ↓
Correlate
  ↓
Assess Risk
  ↓
Document
  ↓
Respond
```

The emphasis is on understanding **why an email is suspicious**, rather than simply labeling it as phishing.

---

## Disclaimer

This project is intended for **educational, defensive cybersecurity, and authorized security-analysis purposes only**.

The included analysis logic should not be considered a replacement for enterprise email-security controls, threat-intelligence platforms, or professional incident-response procedures.

Always analyze suspicious files and emails in an appropriately isolated environment.

---

## Author

**Syed Hamza Hussain Shah**

Bachelor of Computer Science — Cybersecurity

University of Wollongong Dubai

Expected Graduation: July 2027

GitHub: `hamzahussain8a-rgb`

---

## Project Status

**Status: Completed — Initial Version**

The current version provides automated local phishing email triage, IOC extraction, HTML/body analysis, attachment hashing, and rule-based risk assessment.

Future iterations will focus on automated threat-intelligence enrichment, authentication analysis, advanced URL detection, and SOC/SIEM integration.
