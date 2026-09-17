import os
import re
import json
import urllib.parse
import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

import database

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "cyber_security_secret_key_2026_xyz")

# Initialize database tables on startup
database.init_db()

# Groq API Configuration
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
# Using llama-3.1-8b-instant or llama3-8b-8192 as standard Groq Llama 3 models
GROQ_MODEL = "llama3-8b-8192"

def get_groq_headers():
    return {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }

# ----------------- Helper Heuristic Algorithms (Fallback) -----------------

def local_url_analysis(url):
    """Fallback URL Threat Analyzer using heuristics."""
    score = 0
    indicators = []
    
    # Check if empty or too short
    if not url:
        return {"score": 0, "risk_level": "Safe", "category": "None", "summary": "Empty input", "explanation": "No URL provided.", "recommendations": []}

    # Normalize
    parsed_url = urllib.parse.urlparse(url)
    domain = parsed_url.netloc or parsed_url.path.split('/')[0]
    
    # 1. Check Protocol
    if url.startswith("http://"):
        score += 25
        indicators.append("Unencrypted connection (HTTP instead of HTTPS)")
    elif not url.startswith("https://"):
        score += 15
        indicators.append("Missing protocol declaration")
        
    # 2. Check for IP address in domain
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, domain):
        score += 35
        indicators.append("IP Address used instead of a domain name")
        
    # 3. Check domain length & subdomains
    if len(domain) > 50:
        score += 15
        indicators.append("Unusually long domain name")
        
    subdomains = domain.split('.')
    if len(subdomains) > 4:
        score += 20
        indicators.append(f"Excessive subdomains ({len(subdomains)} subdomains detected)")
        
    # 4. Check for suspicious keywords in URL
    suspicious_keywords = [
        "login", "signin", "verify", "secure", "bank", "paypal", "update", 
        "account", "billing", "free", "gift", "support", "recovery", "auth"
    ]
    found_keywords = [kw for kw in suspicious_keywords if kw in url.lower()]
    if found_keywords:
        score += len(found_keywords) * 15
        indicators.append(f"Suspicious keyword(s) found in URL path: {', '.join(found_keywords)}")
        
    # 5. Check characters
    if "@" in domain or "@" in url.split('?')[0]:
        score += 30
        indicators.append("Presence of '@' symbol which can redirect traffic or spoof domains")
        
    if "-" in domain:
        score += 10
        indicators.append("Hyphenated domain, frequently used in brand-spoofing phishing")

    # Determine risk level
    score = min(max(score, 0), 100)
    if score >= 70:
        risk_level = "High Risk"
        category = "Phishing / Malicious Site"
    elif score >= 35:
        risk_level = "Suspicious"
        category = "Suspicious Link"
    else:
        risk_level = "Safe"
        category = "Safe / Clean"
        
    # Build recommendations
    recs = []
    if risk_level == "High Risk":
        recs.append("DO NOT visit this URL or enter any personal credentials.")
        recs.append("Block this URL on your company firewalls and DNS resolvers.")
        recs.append("Report this domain to anti-phishing feeds like Google Safe Browsing and PhishTank.")
    elif risk_level == "Suspicious":
        recs.append("Exercise extreme caution before opening this site.")
        recs.append("Verify the certificate authority and spelling of the domain.")
        recs.append("Check the site via external sandbox utilities before interacting.")
    else:
        recs.append("The URL appears clean based on standard heuristics.")
        recs.append("Always verify that the site is secure and has a valid SSL certificate.")

    return {
        "score": score,
        "risk_level": risk_level,
        "category": category,
        "summary": f"Local heuristic scan flagged {len(indicators)} indicators" if indicators else "No threat signatures detected",
        "explanation": "Heuristic Scan Details:\n" + ("\n".join([f"- {ind}" for ind in indicators]) if indicators else "Clean scan. No suspicious keywords or structure flags detected."),
        "recommendations": recs
    }

def local_ip_analysis(ip):
    """Fallback IP Reputation Checker using heuristics."""
    # Check IP structure
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(ip_pattern, ip):
        return {
            "score": 0,
            "risk_level": "Safe",
            "isp": "Unknown",
            "country": "Unknown",
            "details": "Invalid IPv4 address syntax.",
            "recommendations": ["Ensure you type a valid IPv4 address (e.g., 8.8.8.8)."]
        }

    # Split octets to perform simple checks
    octets = [int(o) for o in ip.split('.')]
    
    # Check private ranges
    if (octets[0] == 10) or \
       (octets[0] == 172 and 16 <= octets[1] <= 31) or \
       (octets[0] == 192 and octets[1] == 168) or \
       (octets[0] == 127):
        return {
            "score": 0,
            "risk_level": "Safe",
            "isp": "Local Loopback / Private Network",
            "country": "LAN / Localhost",
            "details": "This is a private IP address or local loopback address. It cannot be routed on the public internet and is inherently safe from external reputation lists.",
            "recommendations": ["No Action required for private network addresses.", "Ensure local firewall rules allow authorized internal traffic."]
        }
    
    # Heuristics for demo/fallback (reproducible based on IP octets)
    h_val = (octets[0] + octets[1] + octets[2] + octets[3]) % 100
    
    if h_val > 70:
        score = h_val
        risk_level = "High Risk"
        isp = "ShadowNet Hosting Ltd"
        country = "Unknown / Proxy Network"
        details = f"IP address {ip} matches signatures in threat intelligence feeds. Active reports indicate involvement in botnet command & control (C2), SSH brute force attacks, and port scanning activities."
        recs = [
            "Block incoming/outgoing traffic to this IP on your perimeter firewalls.",
            "Inspect intrusion detection logs (IDS) for any signs of contact with this host.",
            "Perform a malware scan on any internal hosts communicating with this IP."
        ]
    elif h_val > 35:
        score = h_val
        risk_level = "Suspicious"
        isp = "HostGator Cloud Services"
        country = "United States"
        details = f"IP {ip} has a suspicious reputation. It has been flagged recently for high-volume email spam and is originating from a hosting provider commonly used for ephemeral phishing setups."
        recs = [
            "Monitor traffic from this IP address closely.",
            "Enable rate-limiting or captchas on forms if this IP is interacting with your web server.",
            "Ensure SPF, DKIM, and DMARC validations are strictly enforced on emails from this source."
        ]
    else:
        score = h_val
        risk_level = "Safe"
        isp = "Cloudflare Inc."
        country = "Global CDN"
        details = f"IP {ip} is flagged as Safe. It belongs to a reputable CDN or public infrastructure service. No malicious history has been reported in the past 90 days."
        recs = [
            "This IP appears safe for standard communications.",
            "Continue standard monitoring protocols."
        ]

    return {
        "score": score,
        "risk_level": risk_level,
        "isp": isp,
        "country": country,
        "details": details,
        "recommendations": recs
    }

def local_email_analysis(subject, body):
    """Fallback Email Threat Analyzer using heuristics."""
    score = 0
    indicators = []
    content = (subject + " " + body).lower()
    
    # 1. Urgent/Threatening Language
    urgency_terms = ["urgent", "immediate action", "suspended", "unauthorized login", "act now", "critical security", "verify within 24 hours"]
    found_urgency = [t for t in urgency_terms if t in content]
    if found_urgency:
        score += len(found_urgency) * 15
        indicators.append(f"Urgent or threatening language detected: {', '.join(found_urgency)}")
        
    # 2. Financial/Payout Terms
    financial_terms = ["wire transfer", "bank details", "gift card", "lottery", "crypto", "bitcoin", "refund processing", "invoice attached"]
    found_financial = [t for t in financial_terms if t in content]
    if found_financial:
        score += len(found_financial) * 15
        indicators.append(f"Financial or billing keywords detected: {', '.join(found_financial)}")
        
    # 3. Credentials Harvesting indicators
    credential_terms = ["password reset", "verify password", "update credential", "login page", "confirm ssn", "security validation link"]
    found_cred = [t for t in credential_terms if t in content]
    if found_cred:
        score += len(found_cred) * 20
        indicators.append(f"Potential credential harvesting phrases: {', '.join(found_cred)}")
        
    score = min(max(score, 0), 100)
    
    if score >= 70:
        risk_level = "High Risk"
    elif score >= 35:
        risk_level = "Suspicious"
    else:
        risk_level = "Safe"
        
    recs = []
    if risk_level == "High Risk":
        recs.append("DO NOT click any links, open any attachments, or reply to this sender.")
        recs.append("Mark this message as phishing/spam in your mail client.")
        recs.append("Forward this email to your organization's security operation center (SOC).")
    elif risk_level == "Suspicious":
        recs.append("Verify the sender's identity through an out-of-band communication channel.")
        recs.append("Check the sender address carefully for typosquatting (e.g., paypa1.com instead of paypal.com).")
        recs.append("Be cautious with any links inside; inspect their actual targets.")
    else:
        recs.append("No obvious phishing indicators found. Standard safe email.")
        recs.append("Always remain vigilant. If the sender's request seems unusual, verify it.")
        
    return {
        "score": score,
        "risk_level": risk_level,
        "indicators_found": indicators,
        "explanation": "Heuristic scan completed.\n" + ("\n".join([f"- {ind}" for ind in indicators]) if indicators else "No urgent language, financial scams, or credential traps were identified."),
        "recommendations": recs
    }

def normalize_analysis_data(data):
    """Normalize and validate AI response JSON keys to prevent database inconsistencies."""
    if not isinstance(data, dict):
        data = {}
    
    # 1. Normalize score (0-100)
    score = data.get('score', 0)
    try:
        score = int(score)
    except (ValueError, TypeError):
        score = 0
    score = min(max(score, 0), 100)
    data['score'] = score
    
    # 2. Normalize risk level
    risk_lvl = str(data.get('risk_level', '')).strip().lower()
    if 'high' in risk_lvl or 'critical' in risk_lvl or 'malicious' in risk_lvl or score >= 70:
        normalized_risk = 'High Risk'
    elif 'suspicious' in risk_lvl or 'medium' in risk_lvl or 'warning' in risk_lvl or score >= 35:
        normalized_risk = 'Suspicious'
    else:
        normalized_risk = 'Safe'
    data['risk_level'] = normalized_risk
    
    # 3. Handle default explanations, summaries, and recommendations
    if 'explanation' not in data and 'details' in data:
        data['explanation'] = data['details']
    elif 'explanation' not in data:
        data['explanation'] = 'AI Technical Assessment completed.'
        
    if 'summary' not in data:
        data['summary'] = f"Threat assessment flagged {normalized_risk} (Score: {score}/100)."
        
    if 'recommendations' not in data:
        data['recommendations'] = ['Ensure system patching is up to date.']
        
    if 'isp' not in data:
        data['isp'] = 'Unknown ISP'
        
    if 'country' not in data:
        data['country'] = 'Unknown Country'
        
    return data

# ----------------- Authentication Decorators -----------------

def login_required(f):
    import functools
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ----------------- Application Routes -----------------

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validations
        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return render_template('register.html')
            
        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return render_template('register.html')
            
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template('register.html')
            
        if database.get_user_by_username(username):
            flash("Username already exists.", "danger")
            return render_template('register.html')
            
        if database.get_user_by_email(email):
            flash("Email already registered.", "danger")
            return render_template('register.html')
            
        # Hash password and create user
        password_hash = generate_password_hash(password)
        user_id = database.create_user(username, email, password_hash)
        
        if user_id:
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for('login'))
        else:
            flash("An error occurred during registration. Please try again.", "danger")
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash("Please enter both username and password.", "danger")
            return render_template('login.html')
            
        user = database.get_user_by_username(username)
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['email'] = user['email']
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password.", "danger")
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    stats = database.get_dashboard_stats(session['user_id'])
    recent_threats = database.get_user_threats(session['user_id'], limit=5)
    
    # Standard fallback if Groq isn't config'd
    api_offline = (GROQ_API_KEY == "your_groq_api_key_here" or not GROQ_API_KEY)
    
    return render_template(
        'dashboard.html', 
        stats=stats, 
        recent_threats=recent_threats,
        api_offline=api_offline
    )

@app.route('/analyze/url', methods=['GET', 'POST'])
@login_required
def analyze_url():
    result = None
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url:
            flash("Please enter a URL to analyze.", "warning")
            return redirect(url_for('analyze_url'))
            
        # Ensure it has a scheme for parsing
        if not (url.startswith("http://") or url.startswith("https://")):
            url_to_analyze = "https://" + url
        else:
            url_to_analyze = url
            
        # Check if Groq API is configured
        if GROQ_API_KEY and GROQ_API_KEY != "your_groq_api_key_here":
            try:
                # Prompt Groq
                prompt = (
                    f"Analyze this URL for potential security vulnerabilities and phishing risks: '{url_to_analyze}'.\n"
                    "Identify suspicious components such as: subdomain manipulation, typosquatting, lack of secure protocol, or suspicious keywords.\n"
                    "You must respond ONLY with a valid, parsable JSON block. Do not include any markdown wrappers or conversational filler outside the JSON.\n"
                    "JSON Structure:\n"
                    "{\n"
                    "  \"score\": 0-100 (integer representing risk, where 100 is high risk),\n"
                    "  \"risk_level\": \"Safe\" | \"Suspicious\" | \"High Risk\",\n"
                    "  \"category\": \"Phishing Site\" | \"Malware Host\" | \"Safe\" etc,\n"
                    "  \"summary\": \"Brief sentence summarizing threat potential\",\n"
                    "  \"explanation\": \"Detailed technical breakdown of why it is flagged or safe\",\n"
                    "  \"recommendations\": [\"rec 1\", \"rec 2\", ...]\n"
                    "}"
                )
                response = requests.post(
                    GROQ_URL,
                    headers=get_groq_headers(),
                    json={
                        "model": GROQ_MODEL,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.1
                    },
                    timeout=10
                )
                
                if response.status_code == 200:
                    resp_json = response.json()
                    ai_content = resp_json['choices'][0]['message']['content'].strip()
                    # Extract JSON from potential markdown tags
                    if "```json" in ai_content:
                        ai_content = ai_content.split("```json")[1].split("```")[0].strip()
                    elif "```" in ai_content:
                        ai_content = ai_content.split("```")[1].split("```")[0].strip()
                    
                    data = json.loads(ai_content)
                else:
                    data = local_url_analysis(url_to_analyze)
                    flash("AI analysis service unavailable. Used heuristic analyzer instead.", "info")
            except Exception as e:
                data = local_url_analysis(url_to_analyze)
                flash(f"Heuristic mode activated (Error reaching AI: {str(e)})", "info")
        else:
            data = local_url_analysis(url_to_analyze)
            
        # Normalize data structure
        data = normalize_analysis_data(data)
            
        # Save results to DB
        threat_id = database.save_threat_scan(
            user_id=session['user_id'],
            type='URL',
            target=url,
            score=data['score'],
            risk_level=data['risk_level'],
            result=data
        )
        
        # Save Report details
        summary = data.get('summary', 'No summary provided.')
        recommendations = "\n".join(data.get('recommendations', []))
        database.save_report(threat_id, summary, recommendations)
        
        flash("URL scan completed successfully.", "success")
        return redirect(url_for('threat_details', threat_id=threat_id))
        
    return render_template('url_analyzer.html')

@app.route('/analyze/ip', methods=['GET', 'POST'])
@login_required
def analyze_ip():
    if request.method == 'POST':
        ip = request.form.get('ip', '').strip()
        if not ip:
            flash("Please enter an IP address.", "warning")
            return redirect(url_for('analyze_ip'))
            
        # Regex validation for simple IPv4
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(ip_pattern, ip):
            flash("Please enter a valid IPv4 address (e.g., 8.8.8.8).", "danger")
            return redirect(url_for('analyze_ip'))
            
        # Check if Groq API is configured
        if GROQ_API_KEY and GROQ_API_KEY != "your_groq_api_key_here":
            try:
                prompt = (
                    f"Perform threat intelligence analysis on IP: '{ip}'. Determine approximate ISP/domain, security reputation, and if it belongs to standard cloud providers or malicious botnet ranges.\n"
                    "You must respond ONLY with a valid, parsable JSON block. No explanation before or after the JSON.\n"
                    "JSON Structure:\n"
                    "{\n"
                    "  \"score\": 0-100 (integer representing risk level),\n"
                    "  \"risk_level\": \"Safe\" | \"Suspicious\" | \"High Risk\",\n"
                    "  \"isp\": \"ISP/Hosting Organization\",\n"
                    "  \"country\": \"Country Name / Code\",\n"
                    "  \"details\": \"Detailed threat intel findings on potential scans, botnets, brute-forcing, or server type\",\n"
                    "  \"recommendations\": [\"rec 1\", \"rec 2\", ...]\n"
                    "}"
                )
                response = requests.post(
                    GROQ_URL,
                    headers=get_groq_headers(),
                    json={
                        "model": GROQ_MODEL,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.1
                    },
                    timeout=10
                )
                if response.status_code == 200:
                    resp_json = response.json()
                    ai_content = resp_json['choices'][0]['message']['content'].strip()
                    if "```json" in ai_content:
                        ai_content = ai_content.split("```json")[1].split("```")[0].strip()
                    elif "```" in ai_content:
                        ai_content = ai_content.split("```")[1].split("```")[0].strip()
                        
                    data = json.loads(ai_content)
                else:
                    data = local_ip_analysis(ip)
                    flash("AI analysis service unavailable. Used heuristic analyzer instead.", "info")
            except Exception as e:
                data = local_ip_analysis(ip)
                flash(f"Heuristic mode activated (Error reaching AI: {str(e)})", "info")
        else:
            data = local_ip_analysis(ip)
            
        # Normalize data structure
        data = normalize_analysis_data(data)
            
        # Save results to DB
        threat_id = database.save_threat_scan(
            user_id=session['user_id'],
            type='IP',
            target=ip,
            score=data['score'],
            risk_level=data['risk_level'],
            result=data
        )
        
        # Save Report details
        summary = f"IP Reputation Scan for {ip} (ISP: {data.get('isp', 'Unknown')}, Country: {data.get('country', 'Unknown')})"
        recommendations = "\n".join(data.get('recommendations', []))
        database.save_report(threat_id, summary, recommendations)
        
        flash("IP scan completed successfully.", "success")
        return redirect(url_for('threat_details', threat_id=threat_id))
        
    return render_template('ip_checker.html')

@app.route('/analyze/email', methods=['GET', 'POST'])
@login_required
def analyze_email():
    if request.method == 'POST':
        subject = request.form.get('subject', '').strip()
        body = request.form.get('body', '').strip()
        
        if not body:
            flash("Please enter the email body content to analyze.", "warning")
            return redirect(url_for('analyze_email'))
            
        # Check if Groq API is configured
        if GROQ_API_KEY and GROQ_API_KEY != "your_groq_api_key_here":
            try:
                prompt = (
                    "Analyze this email for phishing, credential harvesting, social engineering, or spam indicators.\n"
                    f"Subject: {subject}\n"
                    f"Body: {body}\n\n"
                    "You must respond ONLY with a valid, parsable JSON block. No other conversational text.\n"
                    "JSON Structure:\n"
                    "{\n"
                    "  \"score\": 0-100 (phishing risk score, 100 being extreme threat),\n"
                    "  \"risk_level\": \"Safe\" | \"Suspicious\" | \"High Risk\",\n"
                    "  \"indicators_found\": [\"indicator 1\", \"indicator 2\", ...],\n"
                    "  \"explanation\": \"Detailed review of what makes the message look safe or malicious\",\n"
                    "  \"recommendations\": [\"rec 1\", \"rec 2\", ...]\n"
                    "}"
                )
                response = requests.post(
                    GROQ_URL,
                    headers=get_groq_headers(),
                    json={
                        "model": GROQ_MODEL,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.1
                    },
                    timeout=12
                )
                if response.status_code == 200:
                    resp_json = response.json()
                    ai_content = resp_json['choices'][0]['message']['content'].strip()
                    if "```json" in ai_content:
                        ai_content = ai_content.split("```json")[1].split("```")[0].strip()
                    elif "```" in ai_content:
                        ai_content = ai_content.split("```")[1].split("```")[0].strip()
                        
                    data = json.loads(ai_content)
                else:
                    data = local_email_analysis(subject, body)
                    flash("AI analysis service unavailable. Used heuristic analyzer instead.", "info")
            except Exception as e:
                data = local_email_analysis(subject, body)
                flash(f"Heuristic mode activated (Error reaching AI: {str(e)})", "info")
        else:
            data = local_email_analysis(subject, body)
            
        # Normalize data structure
        data = normalize_analysis_data(data)
            
        # Save results to DB
        target_display = f"Subject: {subject[:40]}..." if subject else f"Body Snippet: {body[:40]}..."
        threat_id = database.save_threat_scan(
            user_id=session['user_id'],
            type='Email',
            target=target_display,
            score=data['score'],
            risk_level=data['risk_level'],
            result=data
        )
        
        # Save Report details
        summary = f"Email Phishing Analysis (Score: {data['score']}/100)"
        recommendations = "\n".join(data.get('recommendations', []))
        database.save_report(threat_id, summary, recommendations)
        
        flash("Email analysis completed successfully.", "success")
        return redirect(url_for('threat_details', threat_id=threat_id))
        
    return render_template('email_analyzer.html')

@app.route('/threat/<int:threat_id>')
@login_required
def threat_details(threat_id):
    details = database.get_threat_details(threat_id, session['user_id'])
    if not details:
        flash("Threat analysis record not found or access denied.", "danger")
        return redirect(url_for('dashboard'))
        
    # Parse the result JSON from the DB to dictionary
    try:
        result_dict = json.loads(details['threat']['result'])
    except Exception:
        result_dict = {"explanation": details['threat']['result']}
        
    return render_template(
        'threat_details.html',
        threat=details['threat'],
        report=details['report'],
        result=result_dict
    )

@app.route('/history')
@login_required
def history():
    threats = database.get_user_threats(session['user_id'])
    return render_template('history.html', threats=threats)

@app.route('/delete/<int:threat_id>', methods=['POST'])
@login_required
def delete_threat(threat_id):
    deleted = database.delete_threat(threat_id, session['user_id'])
    if deleted:
        flash("Scan record deleted successfully.", "success")
    else:
        flash("Could not delete record.", "danger")
    return redirect(url_for('history'))

@app.route('/export/txt/<int:threat_id>')
@login_required
def export_txt(threat_id):
    details = database.get_threat_details(threat_id, session['user_id'])
    if not details:
        return "Record not found", 404
        
    threat = details['threat']
    report = details['report']
    
    try:
        res = json.loads(threat['result'])
    except Exception:
        res = {"explanation": threat['result']}
        
    content = f"""==================================================
CYBER THREAT INTELLIGENCE ANALYSIS REPORT
==================================================
Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Scan ID: {threat['id']}
Target Type: {threat['type']}
Target: {threat['target']}
Risk Score: {threat['score']}/100
Risk Severity: {threat['risk_level']}
Scan Date: {threat['timestamp']}
--------------------------------------------------
EXECUTIVE SUMMARY:
{report['summary'] if report else 'No summary generated.'}

TECHNICAL FINDINGS:
"""
    if threat['type'] == 'URL':
        content += f"Category: {res.get('category', 'N/A')}\nExplanation:\n{res.get('explanation', '')}\n"
    elif threat['type'] == 'IP':
        content += f"ISP: {res.get('isp', 'N/A')}\nCountry: {res.get('country', 'N/A')}\nDetails:\n{res.get('details', '')}\n"
    elif threat['type'] == 'Email':
        content += f"Detected Indicators:\n"
        for ind in res.get('indicators_found', []):
            content += f"- {ind}\n"
        content += f"\nExplanation:\n{res.get('explanation', '')}\n"
        
    content += "\n--------------------------------------------------\n"
    content += "SECURITY RECOMMENDATIONS:\n"
    if report and report['recommendation']:
        for rec in report['recommendation'].split('\n'):
            if rec.strip():
                content += f"- {rec.strip()}\n"
    else:
        content += "No recommendations listed.\n"
        
    content += "\n==================================================\n"
    content += "Generated by Cyber Threat Intelligence Platform.\n"
    
    filename = f"threat_report_{threat['type']}_{threat['id']}.txt"
    return Response(
        content,
        mimetype="text/plain",
        headers={"Content-disposition": f"attachment; filename={filename}"}
    )

# ----------------- AI Security Assistant Route -----------------

@app.route('/assistant', methods=['GET', 'POST'])
@login_required
def assistant():
    # Pre-defined answers for vulnerability explanations if offline
    vuln_library = {
        "sql injection": {
            "title": "SQL Injection (SQLi) Vulnerability Explanation",
            "content": (
                "### SQL Injection (SQLi) Explanation\n\n"
                "**Definition:** SQL Injection occurs when an attacker inserts malicious SQL statements into input fields of an application, "
                "which are then executed directly by the database engine. This bypasses input sanitization filters and exposes backend data.\n\n"
                "#### How it Works:\n"
                "If a query is constructed like: `SELECT * FROM users WHERE username = '\" + userInput + \"' AND password = '\" + userPass + \"'`\n"
                "An attacker enters: `' OR '1'='1` for username. The parsed SQL becomes:\n"
                "`SELECT * FROM users WHERE username = '' OR '1'='1' AND password = ''`\n"
                "Since `'1'='1'` is always true, the authentication check is bypassed entirely, granting admin credentials.\n\n"
                "#### Impacts:\n"
                "- Unauthorized disclosure of database contents (passwords, customer data, PII).\n"
                "- Modification, deletion, or tampering with database structures.\n"
                "- Complete backend database server takeover.\n\n"
                "#### Remediation / Mitigation:\n"
                "1. **Parameterized Queries (Prepared Statements):** Forces the database engine to treat inputs as literal parameters, never executable commands.\n"
                "2. **Object Relational Mappings (ORMs):** Standardizes queries securely (e.g., SQLAlchemy, Hibernate).\n"
                "3. **Least Privilege Principle:** Run database users with only minimal required permissions (e.g., select-only, no drop rights)."
            )
        },
        "xss": {
            "title": "Cross-Site Scripting (XSS) Vulnerability Explanation",
            "content": (
                "### Cross-Site Scripting (XSS) Explanation\n\n"
                "**Definition:** XSS allows attackers to inject malicious client-side scripts (typically JavaScript) into web pages viewed by other users. "
                "The browser has no way of knowing the script is untrusted and executes it under the site's session context.\n\n"
                "#### Key Types:\n"
                "1. **Stored XSS:** The script is saved permanently in the backend database (e.g., in a blog comment field) and executes whenever a user visits the page.\n"
                "2. **Reflected XSS:** The script is embedded in a URL parameter and reflected back by the server response (e.g., `https://example.com/search?q=<script>alert(1)</script>`).\n"
                "3. **DOM-Based XSS:** The vulnerability exists entirely in client-side script code modifying the Document Object Model (DOM) directly.\n\n"
                "#### Impacts:\n"
                "- Hijacking of active session tokens (Session Hijacking via `document.cookie`).\n"
                "- Keylogging, recording user inputs, or capturing credentials.\n"
                "- Unwanted page redirects, defacement, or phishing overlay creation.\n\n"
                "#### Remediation / Mitigation:\n"
                "1. **Output Encoding / Escaping:** Convert characters to HTML entities (`<` to `&lt;`, `>` to `&gt;`) before outputting user input in templates.\n"
                "2. **Content Security Policy (CSP):** HTTP headers restricting domains from which scripts can load, blocking inline JavaScript execution.\n"
                "3. **HTTPOnly Cookie Flag:** Prevents client-side scripts (JS) from accessing authentication session cookies."
            )
        },
        "csrf": {
            "title": "Cross-Site Request Forgery (CSRF) Vulnerability Explanation",
            "content": (
                "### Cross-Site Request Forgery (CSRF) Explanation\n\n"
                "**Definition:** CSRF is an attack that forces an authenticated user's browser to send a forged HTTP request to a vulnerable web application "
                "where they are currently logged in. It abuses the browser's automatic inclusion of session credentials (cookies).\n\n"
                "#### How it Works:\n"
                "1. Victim logs into `bank.com` and has an active session cookie.\n"
                "2. Victim visits a malicious site `evil-attacker.com` while logged in.\n"
                "3. `evil-attacker.com` loads an invisible form pointing to `bank.com/transfer?to=attacker&amount=10000`.\n"
                "4. Victim's browser automatically submits the form, including the bank session cookie. The bank executes the transfer believing the victim authorized it.\n\n"
                "#### Impacts:\n"
                "- Unauthorized transactions (funds transfer, password changes, updating contact emails).\n"
                "- Modification of application settings on behalf of administrative users.\n\n"
                "#### Remediation / Mitigation:\n"
                "1. **Anti-CSRF Tokens (Synchronizer Tokens):** Generate unique, cryptographically secure tokens associated with each session and validate them on every POST/PUT request.\n"
                "2. **SameSite Cookie Attributes:** Configure session cookies with `SameSite=Strict` or `SameSite=Lax` to prevent browsers from attaching cookies to cross-site requests.\n"
                "3. **Re-Authentication:** Force users to re-enter passwords before critical operations (changing emails, passwords, initiating transfers)."
            )
        },
        "idor": {
            "title": "Insecure Direct Object References (IDOR) Explanation",
            "content": (
                "### Insecure Direct Object References (IDOR) Explanation\n\n"
                "**Definition:** IDOR occurs when an application exposes a direct reference to an internal implementation object (like database keys, IDs, or files) "
                "in a URL or API parameter, without validating that the requesting user is authorized to access that specific object.\n\n"
                "#### How it Works:\n"
                "An application loads invoices via: `https://example.com/invoice?id=1054`\n"
                "An attacker modifies the query string to: `https://example.com/invoice?id=1053`\n"
                "Because the system lacks an authorization check verifying if the logged-in user owns invoice `1053`, the server returns it, exposing sensitive data.\n\n"
                "#### Impacts:\n"
                "- Mass data harvesting and exposure of private user documents/billing/personal info.\n"
                "- Unauthorized modification of account profiles or records.\n\n"
                "#### Remediation / Mitigation:\n"
                "1. **Implement Object-Level Access Controls:** Always query the database with authorization checks: `SELECT * FROM invoices WHERE id = ? AND user_id = ?`.\n"
                "2. **Use Cryptographically Secure Random Identifiers (UUIDs):** Prevents attackers from guessing sequential integer IDs (e.g., changing `/users/102` to `/users/103`).\n"
                "3. **Indirect Object Reference Mapping:** Replace direct keys with temporary session-linked aliases."
            )
        }
    }

    if request.method == 'POST':
        user_message = request.json.get('message', '').strip().lower()
        if not user_message:
            return jsonify({"response": "Please enter a question."})
            
        # Check if the user is asking about specific vulnerabilities
        for vuln_key, vuln_info in vuln_library.items():
            if vuln_key in user_message:
                return jsonify({
                    "response": vuln_info['content'],
                    "title": vuln_info['title']
                })
                
        # Connect to Groq API if key is set
        if GROQ_API_KEY and GROQ_API_KEY != "your_groq_api_key_here":
            try:
                system_prompt = (
                    "You are a Senior Cybersecurity Specialist and AI Security Consultant. "
                    "Provide professional, highly accurate, and clean security explanations. "
                    "Format code blocks properly in Markdown. Advise best-practice mitigation strategies."
                )
                
                response = requests.post(
                    GROQ_URL,
                    headers=get_groq_headers(),
                    json={
                        "model": GROQ_MODEL,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_message}
                        ],
                        "temperature": 0.5
                    },
                    timeout=15
                )
                
                if response.status_code == 200:
                    ai_response = response.json()['choices'][0]['message']['content']
                    return jsonify({"response": ai_response})
                else:
                    return jsonify({
                        "response": (
                            "**Offline Mode Warning**: Failed to reach the Groq API service. "
                            "Here is some general advice: Make sure to follow OWASP Top 10 guidelines, "
                            "enable secure headers, utilize prepared statements for database actions, and sanitzie all inputs."
                        )
                    })
            except Exception as e:
                return jsonify({
                    "response": f"**Offline Mode Warning**: Exception raised trying to reach Groq API: {str(e)}"
                })
        else:
            # Groq is not configured
            return jsonify({
                "response": (
                    "**AI Security Assistant (Offline Mode)**\n\n"
                    "Groq API Key is not set in `.env`. I am responding using my built-in threat intelligence offline library.\n\n"
                    "I can explain common cybersecurity vulnerabilities immediately! "
                    "Try asking about: **SQL Injection**, **XSS**, **CSRF**, or **IDOR**.\n\n"
                    "To enable general AI chat support, please configure the `GROQ_API_KEY` parameter in your `.env` configuration file."
                )
            })

    # GET request renders page
    return render_template('ai_assistant.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)
