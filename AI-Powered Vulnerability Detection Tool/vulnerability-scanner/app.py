from flask import Flask, render_template, request, jsonify, redirect, url_for
from scanner import VulnerabilityScanner
from ai_analyzer import AIAnalyzer
import sqlite3
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

# Initialize components
scanner = VulnerabilityScanner()
ai_analyzer = AIAnalyzer()

# Database setup
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        results TEXT,
        ai_analysis TEXT
    )
    ''')
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Perform vulnerability scan
    scan_results = scanner.scan(url)
    
    # Perform AI analysis
    ai_result = ai_analyzer.analyze(url)
    
    # Save to database
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO scans (url, results, ai_analysis) VALUES (?, ?, ?)',
        (url, str(scan_results), str(ai_result))
    )
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return jsonify({
        'scan_id': scan_id,
        'results': scan_results,
        'ai_analysis': ai_result
    })

@app.route('/report/<int:scan_id>')
def report(scan_id):
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
    scan = cursor.fetchone()
    
    if not scan:
        return redirect(url_for('index'))
    
    # Parse results
    results = eval(scan['results']) if scan['results'] else []
    ai_analysis = eval(scan['ai_analysis']) if scan['ai_analysis'] else {}
    
    conn.close()
    
    return render_template('report.html', 
                         scan=scan, 
                         results=results, 
                         ai_analysis=ai_analysis)

@app.route('/history')
def history():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM scans ORDER BY timestamp DESC')
    scans = cursor.fetchall()
    
    conn.close()
    
    return render_template('history.html', scans=scans)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)