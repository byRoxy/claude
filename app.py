import os
import sqlite3
import functools
import secrets
import random
import time
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from dotenv import load_dotenv
import requests

load_dotenv()

app = Flask(__name__)

# --- AYARLAR ---
app.secret_key = os.getenv("FLASK_SECRET_KEY", "gizli-anahtar-999")
MASTER_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123") 
DB_PATH = 'chat_history.db'

# --- API MOTORLARI (Biri bozulursa diğerine geçer) ---
API_ENGINES = [
    # 1. Öncelik: Claude (Diwness)
    {
        "url": "https://diwness.cloud/v1/chat/completions",
        "model": "claude-sonnet-4-5-20250929",
        "name": "Diwness (Claude)"
    },
    # 2. Öncelik: Yedek Güç (Pollinations - Çok Kararlıdır)
    {
        "url": "https://text.pollinations.ai/openai",
        "model": "openai", 
        "name": "Pollinations (Backup)"
    }
]

# --- USER AGENTS (Cloudflare Koruması İçin) ---
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
]

def get_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Content-Type": "application/json",
        "Origin": "https://google.com",
        "Referer": "https://google.com/"
    }

# --- VERİTABANI ---
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, access_key TEXT UNIQUE, note TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')
        conn.execute('CREATE TABLE IF NOT EXISTS sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id))')
        conn.execute('CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER, role TEXT, content TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(session_id) REFERENCES sessions(id))')
init_db()

# --- GİRİŞ KONTROLÜ ---
def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session and 'is_admin' not in session: return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'is_admin' not in session: return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- ROTALAR ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        key_input = request.form.get('access_key')
        
        # Admin Girişi
        if key_input == MASTER_PASSWORD:
            session['is_admin'] = True
            session.permanent = True
            return redirect(url_for('admin_panel'))
            
        # Kullanıcı Girişi
        with sqlite3.connect(DB_PATH) as conn:
            user = conn.execute('SELECT id FROM users WHERE access_key = ?', (key_input,)).fetchone()
            if user:
                session['user_id'] = user[0]
                session.permanent = True
                return redirect(url_for('index'))
            else:
                error = "Geçersiz Anahtar!"
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- ADMIN PANELİ ---
@app.route('/admin')
@admin_required
def admin_panel():
    with sqlite3.connect(DB_PATH) as conn:
        # Kullanıcıları ve sohbet sayılarını çek
        users = conn.execute('''
            SELECT u.id, u.access_key, u.note, u.created_at, COUNT(s.id) 
            FROM users u 
            LEFT JOIN sessions s ON u.id = s.user_id 
            GROUP BY u.id 
            ORDER BY u.created_at DESC
        ''').fetchall()
    return render_template('admin.html', users=users)

@app.route('/admin/create_key', methods=['POST'])
@admin_required
def create_key():
    new_key = "CL-" + secrets.token_hex(4).upper()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('INSERT INTO users (access_key, note) VALUES (?, ?)', (new_key, request.form.get('note', 'User')))
    return redirect(url_for('admin_panel'))

# --- KULLANICI SİLME (YENİ EKLENEN KISIM) ---
@app.route('/admin/delete_key/<int:user_id>', methods=['POST'])
@admin_required
def delete_key(user_id):
    with sqlite3.connect(DB_PATH) as conn:
        # 1. Mesajları sil
        conn.execute('DELETE FROM messages WHERE session_id IN (SELECT id FROM sessions WHERE user_id = ?)', (user_id,))
        # 2. Oturumları sil
        conn.execute('DELETE FROM sessions WHERE user_id = ?', (user_id,))
        # 3. Kullanıcıyı sil
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    return redirect(url_for('admin_panel'))

# --- KULLANICI ARAYÜZÜ ---
@app.route('/')
@login_required
def index():
    if 'is_admin' in session: return redirect(url_for('admin_panel'))
    return render_template('index.html')

@app.route('/api/sessions', methods=['GET'])
@login_required
def get_sessions():
    with sqlite3.connect(DB_PATH) as conn:
        sessions = [{"id": r[0], "title": r[1]} for r in conn.execute('SELECT id, title FROM sessions WHERE user_id = ? ORDER BY created_at DESC', (session['user_id'],)).fetchall()]
    return jsonify(sessions)

@app.route('/api/session/<int:session_id>', methods=['GET'])
@login_required
def get_session_history(session_id):
    with sqlite3.connect(DB_PATH) as conn:
        if not conn.execute('SELECT id FROM sessions WHERE id = ? AND user_id = ?', (session_id, session['user_id'])).fetchone(): return jsonify({"error": "No"}), 403
        msgs = [{"role": r[0], "content": r[1]} for r in conn.execute('SELECT role, content FROM messages WHERE session_id = ? ORDER BY id ASC', (session_id,)).fetchall()]
    return jsonify(msgs)

# --- AKILLI CHAT MOTORU (MULTI-PROVIDER + RETRY) ---
@app.route('/api/chat', methods=['POST'])
@login_required
def chat():
    user_id = session['user_id']
    data = request.json
    user_input = data.get("message")
    session_id = data.get("session_id")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    is_new = False
    
    if not session_id:
        cursor.execute('INSERT INTO sessions (user_id, title) VALUES (?, ?)', (user_id, (user_input[:30] + '...') if len(user_input)>30 else user_input))
        session_id = cursor.lastrowid
        is_new = True
    else:
        if not cursor.execute('SELECT id FROM sessions WHERE id = ? AND user_id = ?', (session_id, user_id)).fetchone():
            conn.close()
            return jsonify({"error": "Unauthorized"}), 403

    cursor.execute('INSERT INTO messages (session_id, role, content) VALUES (?, ?, ?)', (session_id, "user", user_input))
    conn.commit()

    history = [{"role": r[0], "content": r[1]} for r in cursor.execute('SELECT role, content FROM messages WHERE session_id = ? ORDER BY id ASC', (session_id,)).fetchall()]

    # --- MOTORLARI DENE ---
    last_error = ""
    success_response = None
    
    for engine in API_ENGINES:
        try:
            print(f"🚀 Deneniyor: {engine['name']}...")
            
            payload = {
                "model": engine['model'],
                "messages": history,
                "temperature": 0.7
            }
            
            headers = {"Content-Type": "application/json"} if "pollinations" in engine['url'] else get_headers()

            response = requests.post(engine['url'], headers=headers, json=payload, timeout=45)

            if response.status_code == 200:
                try:
                    if "choices" in response.json():
                        bot_res = response.json()['choices'][0]['message']['content']
                    else:
                        bot_res = response.text 
                    success_response = bot_res
                    print(f"✅ Başarılı: {engine['name']}")
                    break 
                except:
                    if response.text and len(response.text) > 0:
                        success_response = response.text
                        break
            else:
                print(f"⚠️ {engine['name']} Hatası: {response.status_code}")
                last_error = f"{engine['name']} ({response.status_code})"
                time.sleep(1) 

        except Exception as e:
            print(f"❌ {engine['name']} Bağlantı Koptu: {e}")
            last_error = str(e)
            time.sleep(1)

    if success_response:
        cursor.execute('INSERT INTO messages (session_id, role, content) VALUES (?, ?, ?)', (session_id, "assistant", success_response))
        conn.commit()
        conn.close()
        return jsonify({"response": success_response, "session_id": session_id, "new_session": is_new, "title": user_input[:30]})
    else:
        conn.close()
        return jsonify({"response": f"Tüm sunucular şu an meşgul. ({last_error})"}), 500

@app.route('/api/session/<int:session_id>', methods=['DELETE'])
@login_required
def delete_session(session_id):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('DELETE FROM messages WHERE session_id = ?', (session_id,))
        conn.execute('DELETE FROM sessions WHERE id = ?', (session_id,))
    return jsonify({"status": "deleted"})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
