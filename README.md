# MAIL-MISCONFIG

Mass Email Authentication Misconfiguration Scanner for Bug Bounty Recon and Security Research.

## Features

* Concurrent domain scanning
* SPF misconfiguration detection
* DMARC policy analysis
* DKIM record discovery
* Risk scoring system
* CSV export support
* JSON export support
* Custom DNS resolver support
* Multi-worker scanning engine
* Timeout and retry support
* Colored CLI output

---

# Screenshot

```bash
[*] Loaded 3 domains

[95/100] vulnerable.com
 SPF   : VULNERABLE
 DMARC : WARNING (none)
 DKIM  : MISSING
 Status: VULNERABLE
```

---

# Installation

## Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/mail-misconfig.git
cd mail-misconfig
```

## Initialize Go Module

```bash
go mod init mail-misconfig
```

## Install Dependencies

```bash
go get github.com/fatih/color
```

## Build

```bash
go build mail-misconfig.go
```

---

# Usage

## Scan Single Domain

```bash
./mail-misconfig -single example.com
```

## Scan Multiple Domains

```bash
./mail-misconfig -input domains.txt
```

## Export CSV

```bash
./mail-misconfig -input domains.txt -csv results.csv
```

## Export JSON

```bash
./mail-misconfig -input domains.txt -json results.json
```

## Use Custom DNS

```bash
./mail-misconfig -input domains.txt -dns 8.8.8.8
```

## Increase Workers

```bash
./mail-misconfig -input domains.txt -workers 50
```

---

# Input File Example

## domains.txt

```txt
google.com
facebook.com
github.com
example.com
```

---

# Output Example

```txt
================================================================================
Total Domains: 4
Vulnerable: 1
At Risk: 2
Secure: 1
Errors: 0
================================================================================

[95/100] vulnerable.com
 SPF   : VULNERABLE
 DMARC : WARNING (none)
 DKIM  : MISSING
 Status: VULNERABLE
```

---

# Risk Levels

| Risk Score | Status     | Description                          |
| ---------- | ---------- | ------------------------------------ |
| 70-100     | VULNERABLE | Critical email authentication issues |
| 30-69      | AT_RISK    | Weak or incomplete protections       |
| 0-29       | SECURE     | Properly configured protections      |

---

# Supported Checks

## SPF

Detects:

* Missing SPF
* `+all` misconfigurations
* Weak SPF policies
* `~all` soft fail
* `?all` neutral policy

## DMARC

Detects:

* Missing DMARC
* `p=none`
* `p=quarantine`
* `p=reject`
* Invalid DMARC records

## DKIM

Checks common selectors:

* default
* selector1
* selector2
* google
* amazonses
* sendgrid
* mail
* dkim

---

# Command-Line Flags

| Flag       | Description                   |
| ---------- | ----------------------------- |
| `-input`   | Input file containing domains |
| `-single`  | Scan single domain            |
| `-csv`     | Export CSV report             |
| `-json`    | Export JSON report            |
| `-workers` | Number of concurrent workers  |
| `-timeout` | DNS timeout                   |
| `-retries` | Retry failed lookups          |
| `-dns`     | Custom DNS resolver           |
| `-v`       | Verbose mode                  |

---

# Example Workflows

## Bug Bounty Recon

```bash
./mail-misconfig \
-input targets.txt \
-workers 50 \
-csv vulnerable.csv \
-json results.json
```

## Fast Scan

```bash
./mail-misconfig -input domains.txt -workers 100
```

## Verbose Mode

```bash
./mail-misconfig -input domains.txt -v
```

---

# Limitations

This tool is designed for:

* Security research
* Reconnaissance
* Email authentication posture analysis
* Bug bounty triage

This tool does NOT:

* Guarantee exploitable spoofing
* Perform SMTP exploitation
* Validate DMARC alignment fully
* Implement full RFC SPF parsing

---

# Future Improvements

Planned features:

* SMTP validation
* MX analysis
* Resolver rotation
* Rate limiting
* Passive DNS support
* Real RFC-compliant SPF parser
* DKIM selector bruteforcing
* HTML reporting
* ASN enrichment

---

# License

MIT License

---

# Disclaimer

This tool is intended for:

* Authorized security testing
* Defensive security analysis
* Bug bounty research

Users are responsible for complying with applicable laws and program policies.

---

# GitHub Upload Guide

## Initialize Git

```bash
git init
```

## Add Files

```bash
git add .
```

## Commit

```bash
git commit -m "Initial commit"
```

## Create GitHub Repository

Go to GitHub and create:

```txt
mail-misconfig
```

## Add Remote

```bash
git remote add origin https://github.com/YOUR_USERNAME/mail-misconfig.git
```

## Push

```bash
git branch -M main
git push -u origin main
```

---

# Author

Security Research / Bug Bounty Recon Tool

