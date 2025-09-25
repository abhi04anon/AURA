# 🌐 AURA — Automated Unified Risk Assessment

**AURA** is a Python-based, command-line tool for **web security reconnaissance** and **lightweight vulnerability scanning**.  
It is designed to help security researchers, penetration testers, and system administrators **map, analyze, and report on web applications** in a structured and extensible way.

⚠️ **Legal Disclaimer**  
This tool is provided for **educational and authorized security testing purposes only**.  
Do **not** use AURA against systems you do not own or explicitly have permission to test. Unauthorized usage is illegal and unethical.

---

## ✨ Features

- 🔍 **Website crawling** with adjustable depth and rate limits  
- 🛡️ **Vulnerability checks** (XSS, SQL Injection, sensitive files, weak headers, and more)  
- ⚡ **Lightweight & extensible** architecture (add your own checks easily)  
- 📑 **Report generation** in JSON & plain text (saved under `reports/`)  
- 🐍 Written in **Python 3**, no heavy dependencies  
- ✅ Safe development mode with `--dry-run` (skips network requests)

---

## 🚀 Quickstart

### 1. Clone and set up
```bash
git clone https://github.com/yourusername/aura.git
cd aura
python -m venv .venv
source .venv/bin/activate   # On Windows use: .venv\Scripts\activate
pip install -r requirements.txt
```
