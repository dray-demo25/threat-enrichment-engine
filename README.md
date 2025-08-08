# Threat-Enrichment-Engine - Middleware Repository
This repository powers the backend threat intelligence enrichment for **Your GPT Name**. It acts as a secure middleware that queries and normalizes threat intelligence data from **Shodan**, **VirusTotal**, and **OTX**, returning a structured JSON report to GPT-based systems for enrichment, scoring, and full-spectrum threat modeling.

## 🔍 Purpose
This service was built to enable **automated, repeatable, and real-time threat enrichment** across domains, IPs, and file hashes. Its primary use case is to support GPT via a **custom action** named `Check Reputation`, which provides reputation scores, IOC correlations, vulnerability context, and attack surface insights—mapped to MITRE ATT&CK, VERIS, CVSS, EPSS, and CISA KEV data.

**It transforms raw OSINT into contextual, SOC-ready outputs, suitable for:**
- Automated reputation lookups
- IOC enrichment
- Threat exposure classification
- Adversary behavior mapping
- Scheduled threat advisories

## ⚙️ Tech Stack & Architecture
- **Custom GPT Interface**
- **Node.js (Express.js)** backend
- **Handlebars** for templated PDF or HTML output generation (`report.handlebars`)
- **Render** for CI/CD-based cloud deployment
- **Environment-based API key management** for Shodan, VirusTotal, and OTX

