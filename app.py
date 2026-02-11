import os
import sqlite3
import functools
import secrets
import random
import time
import io
import base64
import PyPDF2
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from dotenv import load_dotenv
import requests

# .env yükle
load_dotenv()

app = Flask(__name__)

# --- AYARLAR ---
app.secret_key = os.getenv("FLASK_SECRET_KEY", "roxy-pro-2026-vision-final")
MASTER_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123") 
DB_PATH = 'chat_history.db'
API_URL = "https://diwness.cloud/v1/chat/completions"

# --- VERİTABANI ---
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, access_key TEXT UNIQUE, note TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')
        conn.execute('CREATE TABLE IF NOT EXISTS sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id))')
        conn.execute('CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER, role TEXT, content TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(session_id) REFERENCES sessions(id))')
init_db()

# --- GÜVENLİK DEKORATÖRLERİ ---
def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session and 'is_admin' not in session: 
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'is_admin' not in session: 
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- ROTALAR ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        key = request.form.get('access_key')
        # Admin Girişi
        if key == MASTER_PASSWORD:
            session['is_admin'] = True
            session.permanent = True
            return redirect(url_for('admin_panel'))
        # Kullanıcı Girişi
        with sqlite3.connect(DB_PATH) as conn:
            user = conn.execute('SELECT id FROM users WHERE access_key = ?', (key,)).fetchone()
            if user:
                session['user_id'] = user[0]
                session.permanent = True
                return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    if 'is_admin' in session: return redirect(url_for('admin_panel'))
    return render_template('index.html')

# --- ADMIN PANELİ FONKSİYONLARI (DÜZELTİLDİ) ---

@app.route('/admin')
@admin_required
def admin_panel():
    with sqlite3.connect(DB_PATH) as conn:
        users = conn.execute('''
            SELECT u.id, u.access_key, u.note, u.created_at, COUNT(s.id) 
            FROM users u LEFT JOIN sessions s ON u.id = s.user_id 
            GROUP BY u.id ORDER BY u.created_at DESC
        ''').fetchall()
    return render_template('admin.html', users=users)

@app.route('/admin/create_key', methods=['POST'])
@admin_required
def create_key():
    new_key = "CL-" + secrets.token_hex(4).upper()
    note = request.form.get('note', 'User')
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('INSERT INTO users (access_key, note) VALUES (?, ?)', (new_key, note))
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete_key/<int:user_id>', methods=['POST'])
@admin_required
def delete_key(user_id):
    with sqlite3.connect(DB_PATH) as conn:
        # Önce kullanıcıya ait mesajları ve seansları sil
        conn.execute('DELETE FROM messages WHERE session_id IN (SELECT id FROM sessions WHERE user_id = ?)', (user_id,))
        conn.execute('DELETE FROM sessions WHERE user_id = ?', (user_id,))
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    return redirect(url_for('admin_panel'))

# --- CHAT MOTORU ---

@app.route('/api/chat', methods=['POST'])
@login_required
def chat():
    user_id = session.get('user_id') or (0 if 'is_admin' in session else None)
    if user_id is None: return jsonify({"error": "Unauthorized"}), 401

    user_input = request.form.get("message", "")
    session_id = request.form.get("session_id")
    file = request.files.get("file")

    ai_content_list = []
    db_display_msg = user_input

    if file:
        fname = file.filename
        mtype = file.content_type
        fdata = file.read()
        
        # 1. GÖRSEL İŞLEME (Base64)
        if mtype.startswith('image/'):
            b64_img = base64.b64encode(fdata).decode('utf-8')
            db_display_msg = f"📎 [Fotoğraf: {fname}] {user_input}"
            ai_content_list.append({
                "type": "image_url",
                "image_url": {"url": f"data:{mtype};base64,{b64_img}"}
            })
        
        # 2. DÖKÜMAN İŞLEME (PDF/TXT)
        elif fname.lower().endswith(('.pdf', '.txt', '.py', '.js', '.html')):
            text = ""
            if fname.lower().endswith('.pdf'):
                reader = PyPDF2.PdfReader(io.BytesIO(fdata))
                for p in reader.pages: text += (p.extract_text() or "") + "\n"
            else:
                text = fdata.decode('utf-8', errors='ignore')
            
            db_display_msg = f"📎 [Dosya: {fname}] {user_input}"
            ai_content_list.append({"type": "text", "text": f"Dosya İçeriği ({fname}):\n{text}"})

    ai_content_list.append({"type": "text", "text": user_input or "Dosyayı analiz et."})

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    if not session_id or session_id == 'null':
        cursor.execute('INSERT INTO sessions (user_id, title) VALUES (?, ?)', (user_id, user_input[:30] or "Dosya Analizi"))
        session_id = cursor.lastrowid
        is_new = True
    else: is_new = False

    cursor.execute('INSERT INTO messages (session_id, role, content) VALUES (?, ?, ?)', (session_id, "user", db_display_msg))
    conn.commit()

    history = [{"role": r[0], "content": r[1]} for r in cursor.execute('SELECT role, content FROM messages WHERE session_id = ? ORDER BY id ASC', (session_id,)).fetchall()]
    history[-1]["content"] = ai_content_list

    try:
        res = requests.post(API_URL, json={"model": "claude-sonnet-4-5-20250929", "messages": history}, timeout=60)
        if res.status_code == 200:
            bot_res = res.json()['choices'][0]['message']['content']
            cursor.execute('INSERT INTO messages (session_id, role, content) VALUES (?, ?, ?)', (session_id, "assistant", bot_res))
            conn.commit()
            conn.close()
            return jsonify({"response": bot_res, "session_id": session_id, "new_session": is_new})
    except: pass
    
    conn.close()
    return jsonify({"response": "Sunucu meşgul veya dosya çok büyük."}), 500

# --- YARDIMCI API'LER ---

@app.route('/api/sessions')
@login_required
def get_sessions():
    uid = session.get('user_id') or 0
    with sqlite3.connect(DB_PATH) as conn:
        return jsonify([{"id": r[0], "title": r[1]} for r in conn.execute('SELECT id, title FROM sessions WHERE user_id = ? ORDER BY created_at DESC', (uid,)).fetchall()])

@app.route('/api/session/<int:id>')
@login_required
def get_hist(id):
    with sqlite3.connect(DB_PATH) as conn:
        return jsonify([{"role": r[0], "content": r[1]} for r in conn.execute('SELECT role, content FROM messages WHERE session_id = ? ORDER BY id ASC', (id,)).fetchall()])

@app.route('/api/session/<int:session_id>', methods=['DELETE'])
@login_required
def delete_session(session_id):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('DELETE FROM messages WHERE session_id = ?', (session_id,))
        conn.execute('DELETE FROM sessions WHERE id = ?', (session_id,))
    return jsonify({"status": "deleted"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
