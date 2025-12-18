#!/usr/bin/env python3
"""
NeoControl v3.0 - Многопользовательская система удаленного контроля
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, session, g
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import os
import sqlite3
import ssl
from datetime import datetime
import logging
from functools import wraps
import secrets
import re

# ==================== НАСТРОЙКИ ====================
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 час
CORS(app, supports_credentials=True)

# Папки
UPLOAD_FOLDER = 'uploads'
DB_FILE = 'neocontrol.db'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Логирование
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('system.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ==================== БАЗА ДАННЫХ ====================
def update_db_schema():
    """Обновление схемы базы данных с новыми полями"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    try:
        # Добавляем новые поля в таблицу users
        c.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in c.fetchall()]
        
        if 'display_name' not in columns:
            c.execute("ALTER TABLE users ADD COLUMN display_name TEXT")
            logger.info("Добавлено поле display_name")
        
        if 'full_name' not in columns:
            c.execute("ALTER TABLE users ADD COLUMN full_name TEXT")
            logger.info("Добавлено поле full_name")
        
        if 'phone_number' not in columns:
            c.execute("ALTER TABLE users ADD COLUMN phone_number TEXT")
            logger.info("Добавлено поле phone_number")
        
        if 'avatar_color' not in columns:
            c.execute("ALTER TABLE users ADD COLUMN avatar_color TEXT DEFAULT '#6366f1'")
            logger.info("Добавлено поле avatar_color")
            
    except Exception as e:
        logger.error(f"Ошибка обновления схемы БД: {e}")
    finally:
        conn.commit()
        conn.close()

def init_db():
    """Инициализация базы данных"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Пользователи
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    ''')
    
    # Логи действий
    c.execute('''
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            action_type TEXT,
            details TEXT,
            ip_address TEXT,
            user_agent TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Сессии
    c.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE,
            user_id INTEGER,
            ip_address TEXT,
            user_agent TEXT,
            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Админ по умолчанию
    try:
        admin_hash = generate_password_hash('admin123')
        c.execute('''
            INSERT OR IGNORE INTO users (username, password_hash, role) 
            VALUES (?, ?, ?)
        ''', ('admin', admin_hash, 'admin'))
    except:
        pass
    
    conn.commit()
    conn.close()
    
    # Обновление схемы
    update_db_schema()
    logger.info("Схема базы данных обновлена")
    logger.info("База данных инициализирована")

def get_db():
    """Подключение к БД"""
    if 'db' not in g:
        g.db = sqlite3.connect(DB_FILE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    """Закрытие подключения"""
    if hasattr(g, 'db'):
        g.db.close()

# ==================== ДЕКОРАТОРЫ ====================
def login_required(f):
    """Требует авторизации"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            log_activity(None, 'access_denied', 'Попытка доступа без авторизации')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    """Требует прав администратора"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            log_activity(session['user_id'], 'access_denied', 'Попытка доступа к админ-панели')
            return jsonify({'error': 'Требуются права администратора'}), 403
        return f(*args, **kwargs)
    return decorated

# ==================== ЛОГИРОВАНИЕ ====================
def log_activity(user_id, action_type, details):
    """Запись действия в лог"""
    try:
        db = get_db()
        username = session.get('username', 'anonymous') if user_id else 'anonymous'
        
        db.execute('''
            INSERT INTO activity_logs 
            (user_id, username, action_type, details, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            user_id,
            username,
            action_type,
            details,
            request.remote_addr,
            request.user_agent.string[:200] if request.user_agent else None
        ))
        
        # Обновление сессии
        if 'session_id' in session:
            db.execute('''
                UPDATE sessions 
                SET last_activity = CURRENT_TIMESTAMP 
                WHERE session_id = ?
            ''', (session['session_id'],))
        
        db.commit()
        
    except Exception as e:
        logger.error(f"Ошибка логирования: {e}")

# ==================== АУТЕНТИФИКАЦИЯ ====================
@app.route('/')
def index():
    """Главная страница"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Страница входа"""
    if request.method == 'GET':
        if 'user_id' in session:
            return redirect(url_for('dashboard'))
        return render_template('login.html')
    
    # POST запрос
    data = request.get_json() or request.form
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({'error': 'Заполните все поля'}), 400
    
    db = get_db()
    user = db.execute('''
        SELECT id, username, password_hash, role 
        FROM users 
        WHERE username = ? AND is_active = 1
    ''', (username,)).fetchone()
    
    if not user or not check_password_hash(user['password_hash'], password):
        log_activity(None, 'login_failed', f'Неудачная попытка входа: {username}')
        return jsonify({'error': 'Неверные учетные данные'}), 401
    
    # Создание сессии
    session.clear()
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['role'] = user['role']
    session['session_id'] = secrets.token_hex(16)
    
    # Запись сессии в БД
    db.execute('''
        INSERT INTO sessions (session_id, user_id, ip_address, user_agent)
        VALUES (?, ?, ?, ?)
    ''', (
        session['session_id'],
        user['id'],
        request.remote_addr,
        request.user_agent.string[:200] if request.user_agent else None
    ))
    
    # Обновление времени входа
    db.execute('''
        UPDATE users 
        SET last_login = CURRENT_TIMESTAMP 
        WHERE id = ?
    ''', (user['id'],))
    
    db.commit()
    
    log_activity(user['id'], 'login', 'Успешный вход в систему')
    
    return jsonify({
        'success': True,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'role': user['role']
        }
    })

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Регистрация"""
    if request.method == 'GET':
        return render_template('register.html')
    
    data = request.get_json() or request.form
    username = data.get('username', '').strip()
    password = data.get('password', '')
    email = data.get('email', '').strip()
    
    if not username or not password:
        return jsonify({'error': 'Заполните обязательные поля'}), 400
    
    if len(password) < 6:
        return jsonify({'error': 'Пароль должен быть не менее 6 символов'}), 400
    
    db = get_db()
    
    # Проверка существования пользователя
    existing = db.execute('''
        SELECT id FROM users WHERE username = ?
    ''', (username,)).fetchone()
    
    if existing:
        log_activity(None, 'register_failed', f'Попытка регистрации существующего пользователя: {username}')
        return jsonify({'error': 'Пользователь уже существует'}), 409
    
    # Создание пользователя
    password_hash = generate_password_hash(password)
    try:
        db.execute('''
            INSERT INTO users (username, password_hash, email)
            VALUES (?, ?, ?)
        ''', (username, password_hash, email))
        db.commit()
        
        log_activity(None, 'register_success', f'Зарегистрирован новый пользователь: {username}')
        
        return jsonify({
            'success': True,
            'message': 'Регистрация успешна. Теперь вы можете войти.'
        })
        
    except Exception as e:
        logger.error(f"Ошибка регистрации: {e}")
        return jsonify({'error': 'Внутренняя ошибка сервера'}), 500

@app.route('/logout')
@login_required
def logout():
    """Выход"""
    user_id = session.get('user_id')
    
    # Деактивация сессии
    if 'session_id' in session:
        db = get_db()
        db.execute('''
            UPDATE sessions 
            SET is_active = 0 
            WHERE session_id = ?
        ''', (session['session_id'],))
        db.commit()
    
    session.clear()
    
    log_activity(user_id, 'logout', 'Выход из системы')
    
    return redirect(url_for('login'))

# ==================== ПОЛЬЗОВАТЕЛЬСКИЙ ИНТЕРФЕЙС ====================
@app.route('/dashboard')
@login_required
def dashboard():
    """Основная панель"""
    db = get_db()
    
    # Статистика пользователя
    stats = db.execute('''
        SELECT 
            SUM(CASE WHEN action_type = 'geolocation' THEN 1 ELSE 0 END) as locations,
            SUM(CASE WHEN action_type = 'image_capture' THEN 1 ELSE 0 END) as images
        FROM activity_logs 
        WHERE user_id = ?
    ''', (session['user_id'],)).fetchone()
    
    # Последние действия
    recent_activity = db.execute('''
        SELECT action_type, details, timestamp 
        FROM activity_logs 
        WHERE user_id = ? 
        ORDER BY timestamp DESC 
        LIMIT 10
    ''', (session['user_id'],)).fetchall()
    
    return render_template('dashboard.html',
                         username=session['username'],
                         role=session['role'],
                         stats=dict(stats) if stats else {'locations': 0, 'images': 0},
                         recent_activity=recent_activity)

@app.route('/profile')
@login_required
def profile():
    """Профиль пользователя"""
    db = get_db()
    user = db.execute('''
        SELECT username, email, role, created_at, last_login
        FROM users 
        WHERE id = ?
    ''', (session['user_id'],)).fetchone()
    
    return render_template('profile.html',
                         user=dict(user) if user else {},
                         username=session['username'])

# ==================== API ДЛЯ УПРАВЛЕНИЯ ====================
@app.route('/api/get_location', methods=['POST'])
@login_required
def api_get_location():
    """Получение геолокации"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Нет данных'}), 400
        
        log_activity(session['user_id'], 'geolocation', 
                    f"Координаты: {data.get('lat')}, {data.get('lon')}")
        
        # Сохранение в файл
        filename = f"uploads/location_{session['user_id']}.log"
        with open(filename, 'a', encoding='utf-8') as f:
            f.write(f"{datetime.now()}: {data}\n")
        
        return jsonify({
            'success': True,
            'message': 'Координаты получены',
            'user': session['username']
        })
        
    except Exception as e:
        logger.error(f"Ошибка получения геолокации: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/capture_image', methods=['POST'])
@login_required
def api_capture_image():
    """Захват изображения"""
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'Нет файла изображения'}), 400
        
        file = request.files['image']
        if file.filename == '':
            return jsonify({'error': 'Файл не выбран'}), 400
        
        # Сохранение
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{session['username']}_{timestamp}.jpg"
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        
        log_activity(session['user_id'], 'image_capture',
                    f"Изображение сохранено: {filename}")
        
        return jsonify({
            'success': True,
            'filename': filename,
            'size': os.path.getsize(filepath)
        })
        
    except Exception as e:
        logger.error(f"Ошибка захвата изображения: {e}")
        return jsonify({'error': str(e)}), 500

# ==================== АДМИН-ПАНЕЛЬ ====================
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """Панель администратора"""
    db = get_db()
    
    # Статистика
    stats = db.execute('''
        SELECT 
            (SELECT COUNT(*) FROM users) as total_users,
            (SELECT COUNT(*) FROM sessions WHERE is_active = 1) as active_sessions,
            (SELECT COUNT(*) FROM activity_logs) as total_logs,
            (SELECT COUNT(*) FROM activity_logs WHERE DATE(timestamp) = DATE('now')) as today_logs
    ''').fetchone()
    
    # Последние логи
    recent_logs = db.execute('''
        SELECT username, action_type, details, timestamp 
        FROM activity_logs 
        ORDER BY timestamp DESC 
        LIMIT 20
    ''').fetchall()
    
    return render_template('admin_dashboard.html',
                         stats=dict(stats),
                         recent_logs=recent_logs,
                         username=session['username'])

@app.route('/admin/users')
@admin_required
def admin_users():
    """Управление пользователями"""
    db = get_db()
    users = db.execute('''
        SELECT id, username, email, role, created_at, last_login, is_active
        FROM users 
        ORDER BY created_at DESC
    ''').fetchall()
    
    return render_template('admin_users.html',
                         users=users,
                         username=session['username'])

@app.route('/admin/logs')
@admin_required
def admin_logs():
    """Просмотр логов"""
    db = get_db()
    page = request.args.get('page', 1, type=int)
    per_page = 50
    offset = (page - 1) * per_page
    
    logs = db.execute('''
        SELECT * FROM activity_logs 
        ORDER BY timestamp DESC 
        LIMIT ? OFFSET ?
    ''', (per_page, offset)).fetchall()
    
    total = db.execute('SELECT COUNT(*) FROM activity_logs').fetchone()[0]
    
    return render_template('admin_logs.html',
                         logs=logs,
                         page=page,
                         per_page=per_page,
                         total=total,
                         username=session['username'])

# ==================== НОВЫЕ МАРШРУТЫ ДЛЯ ФРОНТЕНДА ====================
@app.route('/monitor')
@login_required
def monitor():
    """Продвинутый мониторинг"""
    return render_template('advanced_monitor.html',
                         username=session['username'],
                         role=session['role'])

@app.route('/logs')
@login_required
def user_logs():
    """Страница истории действий пользователя"""
    db = get_db()
    
    # Получаем логи текущего пользователя
    user_logs_data = db.execute('''
        SELECT action_type, details, timestamp 
        FROM activity_logs 
        WHERE user_id = ? 
        ORDER BY timestamp DESC 
        LIMIT 50
    ''', (session['user_id'],)).fetchall()
    
    return render_template('user_logs.html',
                         logs=user_logs_data,
                         username=session['username'],
                         user_id=session['user_id'])

@app.route('/api/session_info')
@login_required
def api_session_info():
    """API для получения информации о сессии"""
    db = get_db()
    
    session_data = db.execute('''
        SELECT login_time, last_activity, ip_address
        FROM sessions
        WHERE user_id = ? AND is_active = 1
        ORDER BY last_activity DESC
        LIMIT 1
    ''', (session['user_id'],)).fetchone()
    
    user_stats = db.execute('''
        SELECT 
            COUNT(CASE WHEN action_type = 'geolocation' THEN 1 END) as locations,
            COUNT(CASE WHEN action_type = 'image_capture' THEN 1 END) as images
        FROM activity_logs 
        WHERE user_id = ?
    ''', (session['user_id'],)).fetchone()
    
    return jsonify({
        "success": True,
        "user": {
            "id": session['user_id'],
            "username": session['username'],
            "role": session['role']
        },
        "session": dict(session_data) if session_data else None,
        "stats": dict(user_stats) if user_stats else {"locations": 0, "images": 0},
        "server_time": datetime.now().isoformat()
    })

@app.route('/api/user_activity')
@login_required
def api_user_activity():
    """API для получения активности пользователя"""
    db = get_db()
    
    activities = db.execute('''
        SELECT action_type, details, timestamp 
        FROM activity_logs 
        WHERE user_id = ? 
        ORDER BY timestamp DESC 
        LIMIT 20
    ''', (session['user_id'],)).fetchall()
    
    return jsonify({
        "success": True,
        "activities": [dict(activity) for activity in activities]
    })

@app.route('/api/update_location', methods=['POST'])
@login_required
def api_update_location():
    """Обновленный API для геолокации с реальными координатами"""
    try:
        # Проверяем, переданы ли координаты из формы
        lat = request.form.get('lat') or request.json.get('lat')
        lon = request.form.get('lon') or request.json.get('lon')
        
        if not lat or not lon:
            # Если нет координат в запросе, пробуем получить из браузера
            return jsonify({
                "success": False,
                "error": "Координаты не предоставлены",
                "hint": "Используйте JavaScript navigator.geolocation"
            })
        
        # Логируем действие
        log_activity(session['user_id'], 'geolocation', 
                    f"Координаты получены: {lat}, {lon}")
        
        # Сохраняем в файл
        filename = f"uploads/location_{session['user_id']}.log"
        with open(filename, 'a', encoding='utf-8') as f:
            f.write(f"{datetime.now()}: {lat}, {lon}\n")
        
        return jsonify({
            "success": True,
            "message": "Координаты сохранены",
            "data": {
                "lat": lat,
                "lon": lon,
                "user": session['username']
            }
        })
        
    except Exception as e:
        logger.error(f"Ошибка сохранения геолокации: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# ==================== API ДЛЯ ПРОФИЛЯ ====================

@app.route('/api/update_profile', methods=['POST'])
@login_required
def api_update_profile():
    """Обновление данных профиля"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Нет данных'}), 400
        
        # Валидация nickname (только английские буквы, цифры, подчеркивание)
        if 'username' in data and data['username']:
            new_username = data['username'].strip()
            if not re.match(r'^[a-zA-Z0-9_]{3,20}$', new_username):
                return jsonify({'error': 'Никнейм может содержать только английские буквы, цифры и подчеркивание (3-20 символов)'}), 400
            
            # Проверка на уникальность
            db = get_db()
            existing = db.execute(
                "SELECT id FROM users WHERE username = ? AND id != ?",
                (new_username, session['user_id'])
            ).fetchone()
            
            if existing:
                return jsonify({'error': 'Этот никнейм уже занят'}), 409
        
        # Валидация телефона (международный формат)
        if 'phone_number' in data and data['phone_number']:
            phone = data['phone_number'].strip()
            if phone and not re.match(r'^\+?[1-9]\d{1,14}$', phone.replace(' ', '')):
                return jsonify({'error': 'Неверный формат телефона. Используйте международный формат'}), 400
        
        # Валидация ФИО (кириллица, пробелы, дефисы)
        if 'full_name' in data and data['full_name']:
            full_name = data['full_name'].strip()
            if full_name and not re.match(r'^[а-яА-ЯёЁ\s\-]{2,50}$', full_name):
                return jsonify({'error': 'ФИО может содержать только кириллические буквы, пробелы и дефисы'}), 400
        
        # Обновление данных
        db = get_db()
        updates = []
        values = []
        
        if 'username' in data:
            updates.append("username = ?")
            values.append(data['username'] if data['username'] else None)
        
        if 'display_name' in data:
            updates.append("display_name = ?")
            values.append(data['display_name'] if data['display_name'] else None)
        
        if 'full_name' in data:
            updates.append("full_name = ?")
            values.append(data['full_name'] if data['full_name'] else None)
        
        if 'phone_number' in data:
            updates.append("phone_number = ?")
            values.append(data['phone_number'] if data['phone_number'] else None)
        
        if 'avatar_color' in data:
            updates.append("avatar_color = ?")
            values.append(data['avatar_color'] if data['avatar_color'] else None)
        
        if updates:
            values.append(session['user_id'])
            query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
            db.execute(query, values)
            db.commit()
            
            # Обновление сессии
            if 'username' in data and data['username']:
                session['username'] = data['username']
        
        log_activity(session['user_id'], 'profile_update', 'Обновление данных профиля')
        
        return jsonify({
            'success': True,
            'message': 'Профиль обновлен'
        })
        
    except Exception as e:
        logger.error(f"Ошибка обновления профиля: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user_profile')
@login_required
def api_user_profile():
    """Получение полных данных профиля"""
    db = get_db()
    
    user = db.execute('''
        SELECT username, display_name, full_name, email, phone_number, 
               role, created_at, last_login, avatar_color
        FROM users 
        WHERE id = ?
    ''', (session['user_id'],)).fetchone()
    
    if not user:
        return jsonify({'error': 'Пользователь не найден'}), 404
    
    return jsonify({
        'success': True,
        'profile': dict(user)
    })
    
# ==================== ЗАПУСК СЕРВЕРА ====================
if __name__ == '__main__':
    # Инициализация
    init_db()
    
    # Проверка SSL
    SSL_CERT = 'cert.pem'
    SSL_KEY = 'key.pem'
    
    if not os.path.exists(SSL_CERT) or not os.path.exists(SSL_KEY):
        logger.error("SSL сертификаты не найдены!")
        logger.info("Создайте командой:")
        logger.info("openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 -subj '/CN=localhost'")
        exit(1)
    
    # SSL контекст
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(SSL_CERT, SSL_KEY)
    
    # Информация
    import socket
    local_ip = socket.gethostbyname(socket.gethostname())
    
    logger.info("=" * 60)
    logger.info("🚀 NEO CONTROL v3.0 ЗАПУЩЕН")
    logger.info("=" * 60)
    logger.info(f"🔐 Админ: admin / admin123")
    logger.info(f"🌐 Адреса доступа:")
    logger.info(f"   • https://localhost:5000")
    logger.info(f"   • https://{local_ip}:5000")
    logger.info("=" * 60)
    
    # Запуск
    app.run(
        host='0.0.0.0',
        port=5000,
        ssl_context=context,
        debug=False,
        threaded=True
    )