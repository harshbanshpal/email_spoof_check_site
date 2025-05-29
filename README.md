# Email Spoofing Vulnerability Checker

A Flask web application to check if a domain is vulnerable to email spoofing by analyzing MX, SPF, and DMARC DNS records. Users can input their email and domain, get immediate results, and request a detailed PDF report.

---

## Requirements

- Python 3.7 or higher
- pip (Python package manager)

---

## Installation

1. Clone this repository:

   ```bash
   git clone https://github.com/harshbanshpal/email_spoof_check_site
   cd email_spoof_check_site
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt

---

## Running the Application

```bash
   python app.py
   http://127.0.0.1:5000/
