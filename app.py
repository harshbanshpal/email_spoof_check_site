from flask import Flask, render_template, request, jsonify
import dns.resolver
import dns.exception
from fpdf import FPDF
import sqlite3
from datetime import datetime

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            domain TEXT NOT NULL,
            mx BOOLEAN,
            spf TEXT,
            dmarc TEXT,
            vulnerable BOOLEAN,
            checked_at TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            domain TEXT NOT NULL,
            mx BOOLEAN,
            spf TEXT,
            dmarc TEXT,
            vulnerable BOOLEAN,
            requested_at TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def check_mx(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return True if answers else False
    except dns.exception.DNSException:
        return False

def check_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_record = rdata.to_text().strip('"')
            if txt_record.startswith('v=spf1'):
                if '~all' in txt_record:
                    return 'softfail'
                return 'pass'
        return 'missing'
    except dns.exception.DNSException:
        return 'missing'

def check_dmarc(domain):
    try:
        dmarc_domain = '_dmarc.' + domain
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            txt_record = rdata.to_text().strip('"')
            if 'p=none' in txt_record or ('p=quarantine' not in txt_record and 'p=reject' not in txt_record):
                return 'not enabled'
            return 'enabled'
        return 'missing'
    except dns.exception.DNSException:
        return 'missing'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check():
    data = request.json
    domain = data.get('domain')
    user_email = data.get('email')

    mx = check_mx(domain)
    spf = check_spf(domain)
    dmarc = check_dmarc(domain)

    vulnerable = (not mx) or (spf == 'softfail') or (spf == 'missing') or (dmarc != 'enabled')

    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()
    c.execute('''
        INSERT INTO checks (email, domain, mx, spf, dmarc, vulnerable, checked_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (user_email, domain, mx, spf, dmarc, vulnerable, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

    result = {
        'mx': mx,
        'spf': spf,
        'dmarc': dmarc,
        'vulnerable': vulnerable
    }
    return jsonify(result)

@app.route('/report', methods=['POST'])
def report():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    domain = data.get('domain')
    spf = data.get('spf')
    dmarc = data.get('dmarc')
    mx = data.get('mx')
    vulnerable = data.get('vulnerable')

    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()
    c.execute('''
        INSERT INTO reports (name, email, domain, mx, spf, dmarc, vulnerable, requested_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (name, email, domain, mx, spf, dmarc, vulnerable, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"Domain Security Report for {domain}", ln=True, align='C')
    pdf.ln(10)
    pdf.cell(200, 10, txt=f"Requested by: {name} ({email})", ln=True)
    pdf.cell(200, 10, txt=f"MX Record Found: {mx}", ln=True)
    pdf.cell(200, 10, txt=f"SPF Status: {spf}", ln=True)
    pdf.cell(200, 10, txt=f"DMARC Status: {dmarc}", ln=True)
    pdf.cell(200, 10, txt=f"Vulnerable: {'Yes' if vulnerable else 'No'}", ln=True)

    filename = f"report_{domain}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.pdf"
    pdf.output(filename)

    return jsonify({'message': 'Report generated as ' + filename})

if __name__ == '__main__':
    app.run(debug=True)
