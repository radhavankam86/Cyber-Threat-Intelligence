# Cyber Threat Intelligence Dashboard: AI-Powered Real-Time Threat Detection Platform

A professional full-stack cybersecurity application for analyzing potential threats in URLs, IP addresses, and email content. This platform integrates the **Groq API (Llama 3)** for deep cognitive security analysis and features a fallback heuristic evaluation engine if offline.

---

## 🛠️ Technology Stack
*   **Backend:** Python Flask
*   **Database:** SQLite3
*   **Frontend:** HTML5, CSS3, Javascript, Bootstrap 5, Chart.js
*   **AI Integration:** Groq API (Llama 3 LLM completions)

---

## 📂 Project Structure
```text
cybersecurity/
├── app.py                      # Flask routes and application routing engine
├── database.py                 # SQLite schema initialization & DB transactions
├── requirements.txt            # Python library dependencies list
├── .env                        # Configuration file for private keys
├── .env.example                # Example configuration reference
├── README.md                   # Setup and deployment documentation
├── static/
│   ├── css/
│   │   └── style.css           # Modern neon dark cybersecurity styling
│   └── js/
│       └── dashboard.js        # Chart.js initialization logic (Timeline & Doughnut)
└── templates/
    ├── base.html               # Main base template containing sidebar & live clock
    ├── login.html              # Authentication console portal
    ├── register.html           # Node registration portal
    ├── dashboard.html          # Statistics, activity history & visual trends
    ├── url_analyzer.html       # URL link scanner form
    ├── ip_checker.html         # IP Reputation scan form
    ├── email_analyzer.html     # Email Phishing block scan form
    ├── threat_details.html     # Detailed reports and mitigation recommendations
    ├── history.html            # Database scan logs with search filter
    └── ai_assistant.html       # Knowledgebase chatbot panel with Marked.js
```

---

## 🗄️ Database SQLite Schema
The system automatically initializes `cyber_intelligence.db` with three primary tables:

```sql
-- Users Table
CREATE TABLE IF NOT EXISTS Users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);

-- Threats Table (linked to user session)
CREATE TABLE IF NOT EXISTS Threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,         -- 'URL', 'IP', or 'Email'
    target TEXT NOT NULL,       -- URL, IP, or Email subject/snippet
    score INTEGER NOT NULL,     -- Risk score from 0 to 100
    risk_level TEXT NOT NULL,   -- 'Safe', 'Suspicious', or 'High Risk'
    result TEXT NOT NULL,       -- JSON formatted technical details
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES Users(id) ON DELETE CASCADE
);

-- Reports Table
CREATE TABLE IF NOT EXISTS Reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id INTEGER NOT NULL,
    summary TEXT NOT NULL,      -- Executive summary
    recommendation TEXT NOT NULL,-- List of actions separated by newlines
    FOREIGN KEY(threat_id) REFERENCES Threats(id) ON DELETE CASCADE
);
```

---

## 🌐 Routes Map
| Route | Method | Description | Auth Required |
|---|---|---|---|
| `/` | `GET` | Landing redirect to Login / Dashboard | No |
| `/login` | `GET`, `POST` | Authenticate Operator console | No |
| `/register` | `GET`, `POST` | Register Operator identity node | No |
| `/logout` | `GET` | Terminate session & clear cookies | No |
| `/dashboard` | `GET` | Core statistics, historical logs & Chart.js charts | **Yes** |
| `/analyze/url` | `GET`, `POST` | Submit URL for phishing checks | **Yes** |
| `/analyze/ip` | `GET`, `POST` | Check IP address against reputation databases | **Yes** |
| `/analyze/email` | `GET`, `POST` | Scan email content for phishing indicators | **Yes** |
| `/threat/<id>` | `GET` | Comprehensive details, summary, and actionables | **Yes** |
| `/history` | `GET` | Full archived scans log with dynamic filters | **Yes** |
| `/delete/<id>` | `POST` | Purge specific scan log from database | **Yes** |
| `/export/txt/<id>`| `GET` | Download raw text threat analysis report | **Yes** |
| `/assistant` | `GET`, `POST` | AJAX terminal for security chat & vulnerability checks | **Yes** |

---

## ⚡ Setup & Installation

### 1. Prerequisite Checks
Ensure that **Python 3.8+** and `pip` are installed on your machine.

### 2. Configure Environment Keys
Duplicate `.env.example` as `.env` and configure your API credentials:
```bash
# Obtain your API key from: https://console.groq.com/
GROQ_API_KEY=your_actual_groq_api_key
FLASK_SECRET_KEY=generate_a_random_cryptographic_secret_key
```

### 3. Install Dependencies
Open your shell terminal in the project directory and install the requirements:
```bash
pip install -r requirements.txt
```

### 4. Fire up Backend Local Server
Launch Flask:
```bash
python app.py
```
By default, the application will initialize at `http://127.0.0.1:5000/`.

---

## 🚀 Production Deployment Instructions

To deploy this application securely in production (e.g., Linux, VPS, AWS EC2):

### 1. Disable Debug Mode
In `app.py`, change `app.run(debug=True)` to `app.run(debug=False)`. Better yet, use a WSGI server like **Gunicorn**:
```bash
pip install gunicorn
```

### 2. Launching via Gunicorn
Run the WSGI process binding to local sockets:
```bash
gunicorn --workers 3 --bind 127.0.0.1:8000 app:app
```

### 3. Set Up Nginx Reverse Proxy
Install Nginx and set up a configuration file (e.g., `/etc/nginx/sites-available/cyberintel`):
```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /static/ {
        alias /path/to/cybersecurity/static/;
    }
}
```
Link configuration and reload Nginx:
```bash
ln -s /etc/nginx/sites-available/cyberintel /etc/nginx/sites-enabled/
sudo systemctl restart nginx
```

### 4. Enable SSL/HTTPS (Certbot)
Enforce HTTPS via Let's Encrypt:
```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

### 5. Keep Service Active via Systemd
Create a systemd unit file `/etc/systemd/system/cyberintel.service`:
```ini
[Unit]
Description=Cyber Threat Intel Dashboard daemon
After=network.target

[Service]
User=youruser
WorkingDirectory=/path/to/cybersecurity
Environment="PATH=/path/to/cybersecurity/venv/bin"
ExecStart=/path/to/cybersecurity/venv/bin/gunicorn --workers 3 --bind 127.0.0.1:8000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```
Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl start cyberintel
sudo systemctl enable cyberintel
```
