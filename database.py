import sqlite3
import json
from datetime import datetime

DB_FILE = "cyber_intelligence.db"

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    
    # Create Threats table (linked to user_id)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            target TEXT NOT NULL,
            score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            result TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES Users(id) ON DELETE CASCADE
        )
    ''')
    
    # Create Reports table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_id INTEGER NOT NULL,
            summary TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            FOREIGN KEY(threat_id) REFERENCES Threats(id) ON DELETE CASCADE
        )
    ''')
    
    conn.commit()
    conn.close()

# User Operations
def create_user(username, email, password_hash):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO Users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, password_hash)
        )
        conn.commit()
        return cursor.lastrowid
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()

def get_user_by_username(username):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM Users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return user

def get_user_by_email(email):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM Users WHERE email = ?", (email,)).fetchone()
    conn.close()
    return user

# Threat and Report Operations
def save_threat_scan(user_id, type, target, score, risk_level, result):
    conn = get_db_connection()
    cursor = conn.cursor()
    # Serialize result to JSON string if it's a dict or list
    if isinstance(result, (dict, list)):
        result_str = json.dumps(result)
    else:
        result_str = str(result)
        
    cursor.execute(
        "INSERT INTO Threats (user_id, type, target, score, risk_level, result) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, type, target, score, risk_level, result_str)
    )
    threat_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return threat_id

def save_report(threat_id, summary, recommendation):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO Reports (threat_id, summary, recommendation) VALUES (?, ?, ?)",
        (threat_id, summary, recommendation)
    )
    conn.commit()
    conn.close()

def get_user_threats(user_id, limit=None):
    conn = get_db_connection()
    if limit:
        threats = conn.execute(
            "SELECT * FROM Threats WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?",
            (user_id, limit)
        ).fetchall()
    else:
        threats = conn.execute(
            "SELECT * FROM Threats WHERE user_id = ? ORDER BY timestamp DESC",
            (user_id,)
        ).fetchall()
    conn.close()
    return threats

def get_threat_details(threat_id, user_id):
    conn = get_db_connection()
    threat = conn.execute(
        "SELECT * FROM Threats WHERE id = ? AND user_id = ?",
        (threat_id, user_id)
    ).fetchone()
    
    if not threat:
        conn.close()
        return None
        
    report = conn.execute(
        "SELECT * FROM Reports WHERE threat_id = ?",
        (threat_id,)
    ).fetchone()
    
    conn.close()
    return {
        "threat": threat,
        "report": report
    }

def delete_threat(threat_id, user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM Threats WHERE id = ? AND user_id = ?", (threat_id, user_id))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def get_dashboard_stats(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Total Scans
    cursor.execute("SELECT COUNT(*) FROM Threats WHERE user_id = ?", (user_id,))
    total_scans = cursor.fetchone()[0]
    
    # 2. Risk Level Counts
    cursor.execute("SELECT COUNT(*) FROM Threats WHERE user_id = ? AND risk_level = 'High Risk'", (user_id,))
    high_risk = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM Threats WHERE user_id = ? AND risk_level = 'Suspicious'", (user_id,))
    medium_risk = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM Threats WHERE user_id = ? AND risk_level = 'Safe'", (user_id,))
    safe_scans = cursor.fetchone()[0]
    
    # 3. Monthly scan counts for chart (last 6 months)
    # Since SQLite doesn't have elaborate date functions by default in all platforms, we use strftime
    cursor.execute(
        """
        SELECT strftime('%Y-%m', timestamp) as month, COUNT(*) as count 
        FROM Threats 
        WHERE user_id = ? 
        GROUP BY month 
        ORDER BY month DESC 
        LIMIT 6
        """,
        (user_id,)
    )
    monthly_data = cursor.fetchall()
    # Reverse to get chronological order
    monthly_data = monthly_data[::-1]
    
    # 4. Threat Type breakdown (URL, IP, Email) for pie chart
    cursor.execute(
        "SELECT type, COUNT(*) as count FROM Threats WHERE user_id = ? GROUP BY type",
        (user_id,)
    )
    type_data = cursor.fetchall()
    
    conn.close()
    
    return {
        "total_scans": total_scans,
        "high_risk": high_risk,
        "medium_risk": medium_risk,
        "safe_scans": safe_scans,
        "monthly_chart": [{"month": r["month"], "count": r["count"]} for r in monthly_data],
        "type_chart": {r["type"]: r["count"] for r in type_data}
    }
