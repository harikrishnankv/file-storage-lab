#!/usr/bin/env python3
"""
File Storage Lab - Vulnerable Backend API

This application demonstrates UUID v1 vulnerabilities in a file storage system.
Users can upload files, manage documents, and access shared content.

Vulnerabilities (Intentional):
- UUID v1 for user IDs, file IDs, and session tokens
- Predictable file enumeration
- Weak access controls
- No rate limiting
- Temporal correlation attacks possible

Essential API Endpoints for Challenge:
- POST /api/register - User registration
- POST /api/login - User authentication
- POST /api/files/upload - Upload new file
- GET /api/files/{file_id} - Download file
- GET /api/debug/flag - Debug endpoint (hint)
- GET /api/health - Health check
"""

import os
import uuid
import sqlite3
import hashlib
import shutil
import random
import time
import socket
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_file, session, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename
import logging

app = Flask(__name__)
app.secret_key = 'vulnerable-secret-key-for-lab'
CORS(app, supports_credentials=True)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Store recent real activities for activity feed
recent_activities = []

# Track flag.txt creation per user (user_id -> flag_file_id)
user_flag_files = {}

# Configuration
DATABASE = 'database/storage.db'
UPLOAD_FOLDER = 'uploads'  # Changed for Docker compatibility
FRONTEND_FOLDER = '../frontend'  # Used when running without Docker
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'zip'}

# Ensure directories exist
os.makedirs('database', exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def init_database():
    """Initialize the SQLite database with required tables."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            security_question TEXT NOT NULL,
            security_answer_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    ''')
    
    # Create files table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            file_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            mime_type TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_public BOOLEAN DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        )
    ''')
    
    # Create sessions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            is_active BOOLEAN DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        )
    ''')
    
    conn.commit()
    conn.close()
    logger.info("Database initialized successfully")

def migrate_database():
    """Ensure existing databases have required columns (simple migrations)."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    try:
        # Check users table columns
        cursor.execute('PRAGMA table_info(users)')
        columns = {row[1] for row in cursor.fetchall()}

        # Add missing security_question
        if 'security_question' not in columns:
            logger.info("Migrating: adding users.security_question column")
            cursor.execute("""
                ALTER TABLE users
                ADD COLUMN security_question TEXT DEFAULT 'What is your username?'
            """)

        # Add missing security_answer_hash
        if 'security_answer_hash' not in columns:
            logger.info("Migrating: adding users.security_answer_hash column")
            cursor.execute("""
                ALTER TABLE users
                ADD COLUMN security_answer_hash TEXT DEFAULT ''
            """)

        conn.commit()
    except Exception as e:
        logger.error(f"Database migration failed: {e}")
        conn.rollback()
    finally:
        conn.close()

def generate_uuid_v1():
    """Generate a UUID v1 (time-based, predictable)."""
    return str(uuid.uuid1())

def generate_close_uuid_v1(base_uuid_str, max_seconds_diff=0.05):
    """Generate a UUID v1 very close to the base UUID (within max_seconds_diff)."""
    import time
    
    # Wait a tiny random amount (within max_seconds_diff) to ensure close timestamp
    wait_time = random.uniform(0.001, max_seconds_diff)
    time.sleep(wait_time)
    
    # Generate new UUID v1 - it will be close in time to the base UUID
    # UUID v1 uses current time, so waiting a tiny bit ensures they're close
    return str(uuid.uuid1())

def hash_password(password):
    """Simple password hashing (not secure for production)."""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, password_hash):
    """Verify password against hash."""
    return hash_password(password) == password_hash

def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def create_admin_user():
    """Create default admin user."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Check if admin exists
    cursor.execute('SELECT user_id FROM users WHERE username = ?', ('admin',))
    if cursor.fetchone():
        conn.close()
        return
    
    # Create admin user with embedded credentials
    admin_id = generate_uuid_v1()
    admin_password_hash = hash_password('admin123')  # Demo password embedded in source
    admin_security_answer_hash = hash_password('admin')  # Demo security answer
    
    cursor.execute('''
        INSERT INTO users (user_id, username, email, password_hash, security_question, security_answer_hash, role)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (admin_id, 'admin', 'admin@lab.local', admin_password_hash, 'What is your username?', admin_security_answer_hash, 'admin'))
    
    conn.commit()
    conn.close()
    logger.info(f"Admin user created with ID: {admin_id}")
    logger.info("Demo credentials: admin / admin123 (embedded in source code)")

@app.route('/api/register', methods=['POST'])
def register():
    """Register a new user."""
    data = request.get_json()
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '').strip()
    security_question = data.get('security_question', '').strip()
    security_answer = data.get('security_answer', '').strip()
    
    if not all([username, email, password, security_question, security_answer]):
        return jsonify({'error': 'All fields are required'}), 400
    
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Check if username or email already exists
    cursor.execute('SELECT username FROM users WHERE username = ? OR email = ?', (username, email))
    if cursor.fetchone():
        conn.close()
        return jsonify({'error': 'Username or email already exists'}), 409
    
    # Create new user with UUID v1 (VULNERABLE!)
    user_id = generate_uuid_v1()
    password_hash = hash_password(password)
    security_answer_hash = hash_password(security_answer.lower())
    
    cursor.execute('''
        INSERT INTO users (user_id, username, email, password_hash, security_question, security_answer_hash)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (user_id, username, email, password_hash, security_question, security_answer_hash))
    
    conn.commit()
    conn.close()
    
    logger.info(f"New user registered: {username} (ID: {user_id})")
    
    return jsonify({
        'message': 'User registered successfully',
        'user_id': user_id,
        'username': username
    })

@app.route('/api/login', methods=['POST'])
def login():
    """Authenticate user and create session."""
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    
    if not all([username, password]):
        return jsonify({'error': 'Username and password required'}), 400
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Find user
    cursor.execute('''
        SELECT user_id, username, email, password_hash, role 
        FROM users 
        WHERE username = ? AND is_active = 1
    ''', (username,))
    
    user = cursor.fetchone()
    
    if not user or not verify_password(password, user[3]):
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Create session with UUID v1 (VULNERABLE!)
    session_id = generate_uuid_v1()
    expires_at = datetime.now() + timedelta(hours=24)
    
    cursor.execute('''
        INSERT INTO sessions (session_id, user_id, expires_at)
        VALUES (?, ?, ?)
    ''', (session_id, user[0], expires_at))
    
    # Update last login
    cursor.execute('''
        UPDATE users SET last_login = CURRENT_TIMESTAMP 
        WHERE user_id = ?
    ''', (user[0],))
    
    conn.commit()
    conn.close()
    
    # Store session info
    session['user_id'] = user[0]
    session['username'] = user[1]
    session['role'] = user[4]
    session['session_id'] = session_id
    
    logger.info(f"User {username} logged in (Session: {session_id})")
    
    return jsonify({
        'message': 'Login successful',
        'user_id': user[0],
        'username': user[1],
        'email': user[2],
        'role': user[4],
        'session_id': session_id,
        'expires_at': expires_at.isoformat()
    })

@app.route('/api/logout', methods=['POST'])
def logout():
    """Logout user and invalidate session."""
    session_id = session.get('session_id')
    
    if session_id:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE sessions SET is_active = 0 
            WHERE session_id = ?
        ''', (session_id,))
        
        conn.commit()
        conn.close()
    
    session.clear()
    
    return jsonify({'message': 'Logged out successfully'})

@app.route('/api/session/validate', methods=['GET'])
def validate_session():
    """Validate current session and return user info."""
    if 'user_id' not in session:
        return jsonify({'error': 'No active session'}), 401
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Get user info
    cursor.execute('''
        SELECT user_id, username, email, role, created_at, last_login
        FROM users 
        WHERE user_id = ? AND is_active = 1
    ''', (session['user_id'],))
    
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        session.clear()
        return jsonify({'error': 'User not found'}), 401
    
    return jsonify({
        'user_id': user[0],
        'username': user[1],
        'email': user[2],
        'role': user[3],
        'created_at': user[4],
        'last_login': user[5]
    })

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    """Get security question for password reset."""
    data = request.get_json()
    username = data.get('username', '').strip()
    
    if not username:
        return jsonify({'error': 'Username is required'}), 400
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Find user
    cursor.execute('''
        SELECT security_question FROM users 
        WHERE username = ? AND is_active = 1
    ''', (username,))
    
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'security_question': result[0]
    })

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    """Reset password using security question."""
    data = request.get_json()
    username = data.get('username', '').strip()
    security_answer = data.get('security_answer', '').strip()
    new_password = data.get('new_password', '').strip()
    
    if not all([username, security_answer, new_password]):
        return jsonify({'error': 'All fields are required'}), 400
    
    if len(new_password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Find user and verify security answer
    cursor.execute('''
        SELECT user_id, security_answer_hash FROM users 
        WHERE username = ? AND is_active = 1
    ''', (username,))
    
    user = cursor.fetchone()
    
    if not user or not verify_password(security_answer.lower(), user[1]):
        conn.close()
        return jsonify({'error': 'Invalid security answer'}), 401
    
    # Update password
    new_password_hash = hash_password(new_password)
    cursor.execute('''
        UPDATE users SET password_hash = ? WHERE user_id = ?
    ''', (new_password_hash, user[0]))
    
    conn.commit()
    conn.close()
    
    logger.info(f"Password reset for user: {username}")
    
    return jsonify({
        'message': 'Password reset successfully'
    })

@app.route('/api/files', methods=['GET'])
def list_files():
    """List user's files."""
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT file_id, filename, original_filename, file_size, mime_type, created_at, is_public
        FROM files 
        WHERE user_id = ?
        ORDER BY created_at DESC
    ''', (session['user_id'],))
    
    files = cursor.fetchall()
    conn.close()
    
    return jsonify({
        'files': [
            {
                'file_id': file[0],
                'filename': file[1],
                'original_filename': file[2],
                'file_size': file[3],
                'mime_type': file[4],
                'created_at': file[5],
                'is_public': bool(file[6])
            }
            for file in files
        ]
    })

@app.route('/api/files/upload', methods=['POST'])
def upload_file():
    """Upload a new file."""
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400
    
    # Check if this is first or second file in multiple upload
    is_first_file = request.form.get('is_first_file') == 'true'
    is_second_file = request.form.get('is_second_file') == 'true'
    
    # Generate UUID v1 for file (VULNERABLE!)
    file_id = generate_uuid_v1()
    filename = secure_filename(file.filename)
    file_path = os.path.join(UPLOAD_FOLDER, f"{file_id}_{filename}")
    
    # Save file
    file.save(file_path)
    file_size = os.path.getsize(file_path)
    
    # Store file info in database
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Check if user has any files (to determine if we should create flag.txt)
    cursor.execute('SELECT COUNT(*) FROM files WHERE user_id = ?', (session['user_id'],))
    file_count = cursor.fetchone()[0]
    
    # If user has no files, reset flag creation status
    global user_flag_files
    if file_count == 0:
        if session['user_id'] in user_flag_files:
            # Delete old flag file if exists
            old_flag_id = user_flag_files[session['user_id']]
            try:
                old_flag_path = os.path.join(UPLOAD_FOLDER, f"{old_flag_id}_flag.txt")
                if os.path.exists(old_flag_path):
                    os.remove(old_flag_path)
                cursor.execute('DELETE FROM files WHERE file_id = ?', (old_flag_id,))
            except:
                pass
            del user_flag_files[session['user_id']]
    
    cursor.execute('''
        INSERT INTO files (file_id, user_id, filename, original_filename, file_path, file_size, mime_type)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (file_id, session['user_id'], filename, file.filename, file_path, file_size, file.content_type))
    
    flag_file_id = None
    
    # Create flag.txt only if this is the first file in a multiple upload OR user's first file ever
    if is_first_file or (session['user_id'] not in user_flag_files and not is_second_file):
        # IMPORTANT: Delete any existing flag files to ensure only ONE flag exists in the system
        cursor.execute('SELECT file_id, file_path FROM files WHERE filename = ?', ('flag.txt',))
        existing_flags = cursor.fetchall()
        
        for old_flag_id, old_flag_path in existing_flags:
            try:
                # Delete from disk
                if os.path.exists(old_flag_path):
                    os.remove(old_flag_path)
                # Delete from database
                cursor.execute('DELETE FROM files WHERE file_id = ?', (old_flag_id,))
                logger.info(f"Deleted old flag file: {old_flag_id}")
            except Exception as e:
                logger.error(f"Error deleting old flag file {old_flag_id}: {e}")
        
        # Clear user_flag_files tracking (since we're creating a new flag)
        user_flag_files.clear()
        
        # Generate UUID v1 very close to the uploaded file's UUID (within 0.05 seconds)
        flag_file_id = generate_close_uuid_v1(file_id, max_seconds_diff=0.05)
        
        # Create flag.txt file with content
        flag_content = 'FLAG_{{UUID_1_Is_noT_Secur3}}'
        flag_file_path = os.path.join(UPLOAD_FOLDER, f"{flag_file_id}_flag.txt")
        
        with open(flag_file_path, 'w') as f:
            f.write(flag_content)
        
        flag_file_size = os.path.getsize(flag_file_path)
        
        # Store flag.txt in database (associated with admin user or system)
        cursor.execute('SELECT user_id FROM users WHERE role = ? LIMIT 1', ('admin',))
        admin_user = cursor.fetchone()
        admin_user_id = admin_user[0] if admin_user else session['user_id']
        
        cursor.execute('''
            INSERT INTO files (file_id, user_id, filename, original_filename, file_path, file_size, mime_type)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (flag_file_id, admin_user_id, 'flag.txt', 'flag.txt', flag_file_path, flag_file_size, 'text/plain'))
        
        # Track that flag has been created for this user
        user_flag_files[session['user_id']] = flag_file_id
        
        logger.info(f"Flag file created: flag.txt (ID: {flag_file_id}) - close to user file {file_id}")
        logger.info(f"✓ Only ONE flag file exists in system: {flag_file_id}")
    
    conn.commit()
    
    # Get admin username for activity feed
    cursor.execute('SELECT username FROM users WHERE role = ? LIMIT 1', ('admin',))
    admin_result = cursor.fetchone()
    admin_username = admin_result[0] if admin_result else 'admin'
    
    conn.close()
    
    logger.info(f"File uploaded: {file.filename} (ID: {file_id}) by {session['username']}")
    
    # Add user's upload to recent activities
    now = datetime.now()
    user_activity = {
        'username': session['username'],
        'filename': file.filename,
        'is_admin': False,
        'timestamp': now.isoformat(),
        'time_ago': 'just now',
        'formatted_time': now.strftime('%H:%M:%S')
    }
    
    # Add activities to recent activities list
    global recent_activities
    
    # If this is the first file, add admin flag upload immediately after
    if is_first_file or flag_file_id:
        # Admin uploads flag.txt immediately after first file (0.05 seconds later)
        admin_activity_time = now + timedelta(milliseconds=50)  # 0.05 seconds
        admin_activity = {
            'username': admin_username,
            'filename': 'flag.txt',
            'is_admin': True,
            'timestamp': admin_activity_time.isoformat(),
            'time_ago': 'just now',
            'formatted_time': admin_activity_time.strftime('%H:%M:%S')
        }
        # Insert activities in chronological order (oldest first in list, but we'll sort by timestamp later)
        # Insert user activity first (oldest)
        recent_activities.insert(0, user_activity)
        # Insert admin activity after user (newer)
        recent_activities.insert(1, admin_activity)
    else:
        # For second file or subsequent files, just add user activity
        recent_activities.insert(0, user_activity)
    
    # Keep only last 20 activities
    recent_activities = recent_activities[:20]
    
    response_data = {
        'message': 'File uploaded successfully',
        'file_id': file_id,
        'filename': filename,
        'file_size': file_size
    }
    
    # Include flag file ID in response for internal tracking and debugging
    if flag_file_id:
        response_data['flag_file_id'] = flag_file_id
        response_data['debug'] = {
            'flag_uuid': flag_file_id,
            'your_file_uuid': file_id,
            'flag_created': True,
            'message': f'Flag file created! UUID: {flag_file_id}'
        }
        # Enhanced logging for debugging
        logger.info("=" * 70)
        logger.info("🚩 FLAG FILE CREATED - DEBUG INFO")
        logger.info("=" * 70)
        logger.info(f"Your File UUID: {file_id}")
        logger.info(f"Flag File UUID: {flag_file_id}")
        logger.info(f"Flag File Path: {os.path.join(UPLOAD_FOLDER, f'{flag_file_id}_flag.txt')}")
        logger.info(f"Flag Content: FLAG_{{UUID_1_Is_noT_Secur3}}")
        logger.info(f"Access URL: http://localhost:5002/api/files/{flag_file_id}")
        logger.info("=" * 70)
    else:
        response_data['debug'] = {
            'flag_created': False,
            'message': 'No flag file created (not first file upload)'
        }
    
    return jsonify(response_data)

@app.route('/api/files/<file_id>', methods=['GET'])
def download_file(file_id):
    """Download a file (VULNERABLE - accessible to all authenticated users with UUID)."""
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # VULNERABLE: No strict authorization check - any authenticated user can access any file with UUID
    cursor.execute('''
        SELECT file_path, original_filename, mime_type, user_id, is_public
        FROM files 
        WHERE file_id = ?
    ''', (file_id,))
    
    file_info = cursor.fetchone()
    
    if not file_info:
        conn.close()
        return jsonify({'error': 'File not found'}), 404
    
    conn.close()
    
    # Resolve file path - handle both relative and absolute paths
    file_path = file_info[0]
    
    # Get the directory where this script is located (backend directory)
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    
    if not os.path.isabs(file_path):
        # If relative path, resolve it relative to backend directory
        file_path = os.path.join(backend_dir, file_path)
    
    # Normalize the path (remove .., resolve symlinks, etc.)
    file_path = os.path.normpath(file_path)
    
    # Verify the file exists
    if not os.path.exists(file_path):
        # Try alternative: just the filename in uploads folder
        filename_only = os.path.basename(file_info[0])
        alt_path = os.path.join(backend_dir, UPLOAD_FOLDER, filename_only)
        if os.path.exists(alt_path):
            file_path = alt_path
        else:
            logger.error(f"File not found: {file_info[0]} (tried: {file_path}, {alt_path})")
        return jsonify({'error': 'File not found on disk'}), 404
    
    logger.info(f"File downloaded: {file_info[1]} (ID: {file_id}) by {session['username']}")
    
    # VULNERABLE: Any authenticated user can download any file if they know the UUID
    return send_file(
        file_path,
        as_attachment=True,
        download_name=file_info[1],
        mimetype=file_info[2]
    )

@app.route('/api/files/<file_id>', methods=['DELETE'])
def delete_file(file_id):
    """Delete a file."""
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Check file ownership with strict tenant isolation
    cursor.execute('''
        SELECT file_path, user_id FROM files WHERE file_id = ?
    ''', (file_id,))
    
    file_info = cursor.fetchone()
    
    if not file_info:
        conn.close()
        return jsonify({'error': 'File not found'}), 404
    
    # Strict authorization check - tenant isolation
    # Admin can delete any file, users can ONLY delete their own files
    if session['role'] != 'admin' and file_info[1] != session['user_id']:
        conn.close()
        return jsonify({'error': 'Access denied - File not found'}), 404  # Return 404 to hide file existence
    
    # Delete file from disk
    if os.path.exists(file_info[0]):
        os.remove(file_info[0])
    
    # Delete file record
    cursor.execute('DELETE FROM files WHERE file_id = ?', (file_id,))
    
    # Check if user has any files left
    cursor.execute('SELECT COUNT(*) FROM files WHERE user_id = ?', (session['user_id'],))
    remaining_files = cursor.fetchone()[0]
    
    # If no files left, reset flag creation status
    global user_flag_files
    if remaining_files == 0 and session['user_id'] in user_flag_files:
        # Delete flag file
        flag_file_id = user_flag_files[session['user_id']]
        try:
            flag_file_path = os.path.join(UPLOAD_FOLDER, f"{flag_file_id}_flag.txt")
            if os.path.exists(flag_file_path):
                os.remove(flag_file_path)
            cursor.execute('DELETE FROM files WHERE file_id = ?', (flag_file_id,))
        except:
            pass
        del user_flag_files[session['user_id']]
        logger.info(f"Flag file deleted and reset for user {session['user_id']} (all files deleted)")
    
    conn.commit()
    conn.close()
    
    logger.info(f"File deleted: {file_id} by {session['username']}")
    
    return jsonify({'message': 'File deleted successfully'})

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get application statistics."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Count real users
    cursor.execute('SELECT COUNT(*) FROM users WHERE is_active = 1')
    real_user_count = cursor.fetchone()[0]
    
    # Count real files
    cursor.execute('SELECT COUNT(*) FROM files')
    real_file_count = cursor.fetchone()[0]
    
    # Count real active sessions
    cursor.execute('SELECT COUNT(*) FROM sessions WHERE is_active = 1 AND expires_at > datetime("now")')
    real_session_count = cursor.fetchone()[0]
    
    # Total file size
    cursor.execute('SELECT SUM(file_size) FROM files')
    total_size = cursor.fetchone()[0] or 0
    
    conn.close()
    
    # Return fake high numbers to simulate large platform
    # Base numbers: 1000+ users, 800+ active users, high file count
    fake_user_count = max(1000, real_user_count + 987)  # At least 1000
    fake_active_users = max(800, int(fake_user_count * 0.8))  # 80% active (base for animation)
    fake_file_count = max(5000, real_file_count + 4500)  # At least 5000 files (base for animation)
    
    return jsonify({
        'users': fake_user_count,
        'active_users': fake_active_users,  # Base for animation
        'files': fake_file_count,  # Base for animation
        'total_storage_bytes': total_size,
        'total_storage_mb': round(total_size / (1024 * 1024), 2)
    })

@app.route('/api/activity/feed', methods=['GET'])
def get_activity_feed():
    """Get activity feed showing real and simulated file uploads."""
    import random
    
    # Get real admin username if exists
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT username FROM users WHERE role = ? LIMIT 1', ('admin',))
    admin_result = cursor.fetchone()
    admin_username = admin_result[0] if admin_result else 'admin'
    conn.close()
    
    # Start with recent real activities
    global recent_activities
    activities = []
    now = datetime.now()
    
    # Add recent real activities (user uploads + admin responses)
    for activity in recent_activities[:5]:  # Include last 5 real activities
        # Update time_ago for real activities
        activity_time = datetime.fromisoformat(activity['timestamp'])
        seconds_ago = int((now - activity_time).total_seconds())
        activity['time_ago'] = format_time_ago(seconds_ago) if seconds_ago > 0 else 'just now'
        activities.append(activity)
    
    # Fake usernames pool (mix of realistic names)
    fake_usernames = [
        'jennifer_m', 'mike_taylor', 'sarah_k', 'david_chen', 'lisa_w', 'john_doe',
        'emily_r', 'chris_brown', 'amanda_l', 'robert_s', 'jessica_m', 'michael_j',
        'ashley_t', 'james_w', 'nicole_h', 'william_d', 'michelle_k', 'daniel_p',
        'stephanie_l', 'matthew_r', 'laura_b', 'ryan_c', 'kelly_m', 'kevin_t',
        'rachel_g', 'brian_l', 'kimberly_s', 'jason_m', 'angela_w', 'eric_h',
        admin_username  # Include admin in the pool
    ]
    
    # File types and names
    file_types = [
        ('document.pdf', 'application/pdf'),
        ('presentation.pptx', 'application/vnd.openxmlformats-officedocument.presentationml.presentation'),
        ('spreadsheet.xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'),
        ('report.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'),
        ('photo.jpg', 'image/jpeg'),
        ('screenshot.png', 'image/png'),
        ('data.csv', 'text/csv'),
        ('notes.txt', 'text/plain'),
        ('archive.zip', 'application/zip'),
        ('image.png', 'image/png'),
        ('document.pdf', 'application/pdf'),
        ('file.doc', 'application/msword')
    ]
    
    # Generate additional fake activities (10-15 total, minus real ones)
    num_fake_activities = random.randint(10, 15) - len(activities)
    if num_fake_activities < 0:
        num_fake_activities = 5
    
    for i in range(num_fake_activities):
        # Admin should appear frequently but with random files (not sensitive-flag.txt)
        if random.random() < 0.3:
            # Admin uploading random files (NOT sensitive-flag.txt in fake activities)
            username = admin_username
            is_admin = True
            # Choose random file, but NOT sensitive-flag.txt
            filename, mime_type = random.choice(file_types)
        else:
            # Regular users
            username = random.choice([u for u in fake_usernames if u != admin_username])
            is_admin = False
            filename, mime_type = random.choice(file_types)
        
        # Random time in the last 5 minutes
        seconds_ago = random.randint(0, 300)
        activity_time = now - timedelta(seconds=seconds_ago)
        
        activities.append({
            'username': username,
            'filename': filename,
            'is_admin': is_admin,
            'timestamp': activity_time.isoformat(),
            'time_ago': format_time_ago(seconds_ago),
            'formatted_time': activity_time.strftime('%H:%M:%S')
        })
    
    # Sort by timestamp (most recent first)
    activities.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return jsonify({
        'activities': activities
    })

def format_time_ago(seconds):
    """Format seconds into human-readable time ago string."""
    if seconds < 60:
        return f"{seconds}s ago"
    elif seconds < 3600:
        minutes = seconds // 60
        return f"{minutes}m ago"
    else:
        hours = seconds // 3600
        return f"{hours}h ago"

@app.route('/api/admin/users', methods=['GET'])
def admin_list_users():
    """List all users (admin only)."""
    if 'user_id' not in session or session['role'] != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT user_id, username, email, role, created_at, last_login, is_active
        FROM users 
        ORDER BY created_at DESC
    ''')
    
    users = cursor.fetchall()
    conn.close()
    
    return jsonify({
        'users': [
            {
                'user_id': user[0],
                'username': user[1],
                'email': user[2],
                'role': user[3],
                'created_at': user[4],
                'last_login': user[5],
                'is_active': bool(user[6])
            }
            for user in users
        ]
    })

@app.route('/api/admin/files', methods=['GET'])
def admin_list_files():
    """List all files (admin only)."""
    if 'user_id' not in session or session['role'] != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT f.file_id, f.filename, f.original_filename, f.file_size, f.mime_type, 
               f.created_at, f.is_public, u.username, u.user_id
        FROM files f
        JOIN users u ON f.user_id = u.user_id
        ORDER BY f.created_at DESC
    ''')
    
    files = cursor.fetchall()
    conn.close()
    
    return jsonify({
        'files': [
            {
                'file_id': file[0],
                'filename': file[1],
                'original_filename': file[2],
                'file_size': file[3],
                'mime_type': file[4],
                'created_at': file[5],
                'is_public': bool(file[6]),
                'owner_username': file[7],
                'owner_id': file[8]
            }
            for file in files
        ]
    })

@app.route('/api/delete_user/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    """Delete a user and all their files (admin only)."""
    if 'user_id' not in session or session['role'] != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    # Prevent admin from deleting themselves
    if user_id == session['user_id']:
        return jsonify({'error': 'Cannot delete your own account'}), 400
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    try:
        # Check if user exists
        cursor.execute('SELECT username FROM users WHERE user_id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return jsonify({'error': 'User not found'}), 404
        
        username = user[0]
        
        # Get all files owned by this user
        cursor.execute('SELECT file_path FROM files WHERE user_id = ?', (user_id,))
        files = cursor.fetchall()
        
        # Delete files from disk
        deleted_files = 0
        for file_path in files:
            if os.path.exists(file_path[0]):
                try:
                    os.remove(file_path[0])
                    deleted_files += 1
                except OSError as e:
                    logger.warning(f"Failed to delete file {file_path[0]}: {e}")
        
        # Delete all user's files from database
        cursor.execute('DELETE FROM files WHERE user_id = ?', (user_id,))
        files_deleted = cursor.rowcount
        
        # Delete all user's sessions
        cursor.execute('DELETE FROM sessions WHERE user_id = ?', (user_id,))
        sessions_deleted = cursor.rowcount
        
        # Delete user account
        cursor.execute('DELETE FROM users WHERE user_id = ?', (user_id,))
        user_deleted = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        if user_deleted > 0:
            logger.info(f"Admin {session['username']} deleted user {username} (ID: {user_id})")
            logger.info(f"Deleted {files_deleted} files, {sessions_deleted} sessions, {deleted_files} files from disk")
            
            return jsonify({
                'message': f'User {username} deleted successfully',
                'files_deleted': files_deleted,
                'sessions_deleted': sessions_deleted,
                'user_id': user_id
            })
        else:
            return jsonify({'error': 'Failed to delete user'}), 500
            
    except Exception as e:
        conn.rollback()
        conn.close()
        logger.error(f"Error deleting user {user_id}: {e}")
        return jsonify({'error': 'Failed to delete user'}), 500

@app.route('/api/users/<user_id>', methods=['DELETE'])
def delete_own_account(user_id):
    """Delete own account (users can delete themselves)."""
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    # Users can only delete their own account
    if user_id != session['user_id']:
        return jsonify({'error': 'Can only delete your own account'}), 403
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    try:
        # Get user info
        cursor.execute('SELECT username FROM users WHERE user_id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return jsonify({'error': 'User not found'}), 404
        
        username = user[0]
        
        # Get all files owned by this user
        cursor.execute('SELECT file_path FROM files WHERE user_id = ?', (user_id,))
        files = cursor.fetchall()
        
        # Delete files from disk
        deleted_files = 0
        for file_path in files:
            if os.path.exists(file_path[0]):
                try:
                    os.remove(file_path[0])
                    deleted_files += 1
                except OSError as e:
                    logger.warning(f"Failed to delete file {file_path[0]}: {e}")
        
        # Delete all user's files from database
        cursor.execute('DELETE FROM files WHERE user_id = ?', (user_id,))
        files_deleted = cursor.rowcount
        
        # Delete all user's sessions
        cursor.execute('DELETE FROM sessions WHERE user_id = ?', (user_id,))
        sessions_deleted = cursor.rowcount
        
        # Delete user account
        cursor.execute('DELETE FROM users WHERE user_id = ?', (user_id,))
        user_deleted = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        if user_deleted > 0:
            logger.info(f"User {username} deleted their own account (ID: {user_id})")
            logger.info(f"Deleted {files_deleted} files, {sessions_deleted} sessions, {deleted_files} files from disk")
            
            # Clear session
            session.clear()
            
            return jsonify({
                'message': f'Account deleted successfully',
                'files_deleted': files_deleted,
                'sessions_deleted': sessions_deleted,
                'user_id': user_id
            })
        else:
            return jsonify({'error': 'Failed to delete account'}), 500
            
    except Exception as e:
        conn.rollback()
        conn.close()
        logger.error(f"Error deleting user {user_id}: {e}")
        return jsonify({'error': 'Failed to delete account'}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'database': 'connected'
    })

@app.route('/api/debug/flag', methods=['GET'])
def debug_flag_info():
    """Debug endpoint to show flag file information (for verification)."""
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Get user's files
    cursor.execute('''
        SELECT file_id, filename, datetime(created_at) as created
        FROM files 
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 5
    ''', (session['user_id'],))
    user_files = cursor.fetchall()
    
    # Get flag files (all flag files in system)
    cursor.execute('''
        SELECT file_id, filename, user_id, datetime(created_at) as created
        FROM files 
        WHERE filename = 'flag.txt'
        ORDER BY created_at DESC
        LIMIT 10
    ''')
    flag_files = cursor.fetchall()
    
    # Check if user has a flag file associated
    global user_flag_files
    user_flag_id = user_flag_files.get(session['user_id'])
    
    conn.close()
    
    debug_info = {
        'user_id': session['user_id'],
        'username': session.get('username', 'unknown'),
        'user_files': [
            {
                'file_id': f[0],
                'filename': f[1],
                'created': f[2]
            } for f in user_files
        ],
        'flag_files_in_system': [
            {
                'file_id': f[0],
                'filename': f[1],
                'owner_user_id': f[2],
                'created': f[3]
            } for f in flag_files
        ],
        'your_flag_file_id': user_flag_id,
        'flag_exists_on_disk': os.path.exists(os.path.join(UPLOAD_FOLDER, f"{user_flag_id}_flag.txt")) if user_flag_id else False
    }
    
    # Add helpful message
    if user_flag_id:
        debug_info['debug_message'] = f'🚩 Your flag file UUID: {user_flag_id}'
        debug_info['access_url'] = f'http://localhost:5002/api/files/{user_flag_id}'
    else:
        debug_info['debug_message'] = 'No flag file created yet. Upload your first file to generate a flag.'
    
    return jsonify(debug_info)

# Frontend serving routes
@app.route('/')
def serve_frontend():
    """Serve the main frontend page."""
    return send_from_directory(FRONTEND_FOLDER, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    """Serve static files from frontend directory."""
    return send_from_directory(FRONTEND_FOLDER, path)

# Removed unnecessary endpoints for challenge

if __name__ == '__main__':
    # Initialize database
    init_database()
    # Run migrations to ensure required columns exist
    migrate_database()
    create_admin_user()
    
    # Function to check if a port is available
    def is_port_available(port):
        """Check if a port is available for binding."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('0.0.0.0', port))
                return True
            except OSError:
                return False
    
    # Try multiple ports if default port is in use
    default_port = 5002
    alternative_ports = [5003, 5004, 5005, 5006]
    all_ports = [default_port] + alternative_ports
    
    port = None
    for test_port in all_ports:
        if is_port_available(test_port):
            port = test_port
            break
    
    if port is None:
        logger.error("❌ All ports are in use. Please free up a port and try again.")
        logger.error(f"   Tried ports: {', '.join(map(str, all_ports))}")
        exit(1)
    
    if port != default_port:
        logger.warning(f"⚠️  Port {default_port} is in use, using port {port} instead")
    
    logger.info("Starting File Storage Lab API...")
    logger.info("🚨 WARNING: This application is intentionally vulnerable!")
    logger.info("Admin credentials are embedded in source code")
    logger.info("")
    logger.info("🌐 Web Interface:")
    logger.info(f"  Main Application: http://localhost:{port}")
    logger.info(f"  Health Check: http://localhost:{port}/api/health")
    logger.info("")
    logger.info("📡 Essential API Endpoints for Challenge:")
    logger.info("  POST /api/register - Register user")
    logger.info("  POST /api/login - Authenticate")
    logger.info("  POST /api/logout - Logout")
    logger.info("  GET /api/session/validate - Validate session")
    logger.info("  POST /api/forgot-password - Get security question")
    logger.info("  POST /api/reset-password - Reset password")
    logger.info("  GET /api/files - List user files")
    logger.info("  POST /api/files/upload - Upload file")
    logger.info("  GET /api/files/{file_id} - Download file")
    logger.info("  GET /api/health - Health check")
    logger.info("")
    logger.info("💡 Hint: There's one more endpoint that will make your job easier!")
    
    # Run in debug mode only if FLASK_ENV is not set to production
    debug_mode = os.environ.get('FLASK_ENV', 'development') != 'production'
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
