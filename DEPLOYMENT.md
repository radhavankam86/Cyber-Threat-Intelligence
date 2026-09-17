# Cyber Threat Intelligence Platform: Deployment & Operational Guide

This document provides a comprehensive overview of the **"Cyber Threat Intelligence Dashboard: AI-Powered Real-Time Threat Detection and Security Analysis Platform"** project structure, SQLite schema, route configuration, and setup/execution guidelines.

---

## 1. Project Structure
The full application layout is structured as follows:

```text
cybersecurity/
│
├── .env                  # Environment configurations (Flask secret key & Groq API key)
├── .env.example          # Template environment configurations
├── app.py                # Main Flask application (Routes, Groq API, scanning logic)
├── database.py           # Database interface (SQLite initialization & queries)
├── requirements.txt      # Python dependencies
├── DEPLOYMENT.md         # This installation & deployment guide
│
├── static/
│   ├── css/
│   │   └── style.css     # Premium dark mode modern cybersecurity styling
│   └── js/
│       └── dashboard.js  # Chart.js initialization & dynamic timeline/pie rendering
│
└── templates/
    ├── base.html         # Base template containing navigation & live clock script
    ├── login.html        # Decrypt credentials access console
    ├── register.html     # Operator registration screen
    ├── dashboard.html    # Main metrics view with timelines & recent scan logs
    ├── url_analyzer.html # URL Phishing indicator input panel
    ├── ip_checker.html   # IP Reputation query input panel
    ├── email_analyzer.html # Email Content phishing scan input panel
    ├── threat_details.html # Scan technical disclosures, metrics gauge, and export
    ├── history.html      # Filterable history list of all logged scans
    └── ai_assistant.html # Llama 3 conversational AI security specialist
```

---

## 2. SQLite Database Schema
The SQLite database file (`cyber_intelligence.db`) is initialized automatically on startup by calling `database.init_db()` in `app.py`. The tables conform to the following schema:

```sql
-- 1. Users Table
CREATE TABLE Users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);

-- 2. Threats Table (tracks target inputs, scores, and serialized JSON result metadata)
CREATE TABLE Threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,         -- 'URL', 'IP', or 'Email'
    target TEXT NOT NULL,       -- Analyzed object name/subject
    score INTEGER NOT NULL,     -- Risk score from 0 to 100
    risk_level TEXT NOT NULL,   -- 'Safe', 'Suspicious', or 'High Risk'
    result TEXT NOT NULL,       -- Stringified JSON object containing detailed findings
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES Users(id) ON DELETE CASCADE
);

-- 3. Reports Table (tracks executive summaries and mitigation checklists)
CREATE TABLE Reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id INTEGER NOT NULL,
    summary TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    FOREIGN KEY(threat_id) REFERENCES Threats(id) ON DELETE CASCADE
);
```

---

## 3. Flask Routes Mapping

The endpoints configured in `app.py` map as follows:

| Endpoint | HTTP Method | Auth Required | Description |
|---|---|---|---|
| `/` | `GET` | No | Automatically redirects to `/dashboard` (if logged in) or `/login` |
| `/register` | `GET`, `POST` | No | Registers a new operator, validates inputs, and hashes passwords |
| `/login` | `GET`, `POST` | No | Authenticates operational credentials and starts user session |
| `/logout` | `GET` | Yes | Clears session identifiers and redirects to login console |
| `/dashboard` | `GET` | Yes | Shows aggregated database stats, timeline trends, and recent logs |
| `/analyze/url` | `GET`, `POST` | Yes | Receives URL targets, executes Llama 3 / heuristic checks, and saves report |
| `/analyze/ip` | `GET`, `POST` | Yes | Receives IP targets, checks subnet categories / reputation, and saves report |
| `/analyze/email` | `GET`, `POST` | Yes | Receives Subject/Body, checks urgency indices / phishing flags, and saves report |
| `/threat/<id>` | `GET` | Yes | Renders full technical breakdown, risk index radial, and mitigation checklists |
| `/delete/<id>` | `POST` | Yes | Purges scan records from database tables |
| `/export/txt/<id>`| `GET` | Yes | Streams threat assessment report as a downloadable TXT document |
| `/assistant` | `GET`, `POST` | Yes | AI terminal chat. Directly queries Groq API or resolves specific local questions |

---

## 4. Setup and Installation

### Prerequisites
Make sure you have **Python 3.8+** installed on your workstation.

### Step 1: Clone or Navigate to the Workspace
Open your command terminal (Powershell or Command Prompt) and change directories to the project folder:
```cmd
cd "C:\Users\RADHA\OneDrive\Desktop\cybersecurity"
```

### Step 2: Set Up Virtual Environment (Recommended)
Creating an isolated environment keeps dependencies tidy:
```cmd
python -m venv venv
venv\Scripts\activate
```

### Step 3: Install Required Dependencies
Install the Flask, Dotenv, and Requests packages:
```cmd
pip install -r requirements.txt
```

### Step 4: Configure Groq API Key
The `.env` configuration file contains:
```env
GROQ_API_KEY=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
FLASK_SECRET_KEY=cyber_intelligence_dashboard_secret_key_2026_x99
```
*Note: The actual active Groq API Key has been preset directly in `.env`. Feel free to adjust the `FLASK_SECRET_KEY` if running in production.*

---

## 5. Execution

To start the local developer server, execute:
```cmd
python app.py
```

Upon start, the console will output:
```text
 * Serving Flask app 'app'
 * Debug mode: on
 * Running on http://127.0.0.1:5000
```
Open your web browser and navigate to **`http://127.0.0.1:5000`** to access the dashboard.

---

## 6. Functional Capabilities & AI Fail-safe
- **AI Integrations**: When active, the system queries Groq's Llama 3 model `llama3-8b-8192` with strict instructions to output parsable JSON formats matching the security engine requirement.
- **Graceful Fallbacks**: If the internet is disconnected, the server times out, or the API quota is exceeded, the analyzers will automatically flag an informational notification and fallback to a custom **local heuristic classifier engine** matching standard phishing signs (malicious keywords, HTTP/HTTPS secure protocol checks, loopback/private range detection, and ASN indicators).
- **Knowledge Library**: Clicking SQL Injection, XSS, CSRF, or IDOR tags in the AI Assistant sidebar loads direct explainers instantly from the offline vault without hitting any network endpoints.
