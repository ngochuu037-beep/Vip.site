# admin_routes.py
from flask import Blueprint, request, jsonify, session, render_template, redirect
import hashlib
import uuid
from datetime import datetime
from firebase_helper import FirebaseHelper
from config import Config

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if username == Config.ADMIN_USERNAME and hashlib.sha256(password.encode()).hexdigest() == Config.ADMIN_PASSWORD_HASH:
            session['admin_authenticated'] = True
            session['admin_username'] = username
            return redirect('/dashboard')
        return render_template('admin_login.html', error="Sai username hoặc mật khẩu")
    return render_template('admin_login.html')

@admin_bp.route('/dashboard')
def dashboard():
    if not session.get('admin_authenticated'):
        return redirect('/admin/login')
    return render_template('dashboard.html', admin_username=session.get('admin_username', 'Admin'))

@admin_bp.route('/api/get_users', methods=['GET'])
def get_users():
    if not session.get('admin_authenticated'):
        return jsonify({'success': False, 'error': 'Unauthorized'})
    users = FirebaseHelper.get('/users') or {}
    usages = FirebaseHelper.get('/usage') or {}
    pro_tools = FirebaseHelper.get('/user_pro_tools') or {}
    return jsonify({'success': True, 'users': users, 'usages': usages, 'pro_tools': pro_tools})

@admin_bp.route('/api/update_user', methods=['POST'])
def update_user():
    if not session.get('admin_authenticated'):
        return jsonify({'success': False, 'error': 'Unauthorized'})
    data = request.json
    username = data.get('username')
    new_data = data.get('new_data', {})
    new_password = data.get('new_password')
    if new_password:
        new_data['password'] = hashlib.sha256(new_password.encode()).hexdigest()
    FirebaseHelper.update(f'/users/{username}', new_data)
    if 'is_pro' in new_data:
        FirebaseHelper.update(f'/usage/{username}', {'is_pro': new_data['is_pro']})
    return jsonify({'success': True, 'message': 'Cập nhật thành công'})

@admin_bp.route('/api/delete_user', methods=['POST'])
def delete_user():
    if not session.get('admin_authenticated'):
        return jsonify({'success': False, 'error': 'Unauthorized'})
    username = request.json.get('username')
    FirebaseHelper.delete(f'/users/{username}')
    FirebaseHelper.delete(f'/usage/{username}')
    FirebaseHelper.delete(f'/user_pro_tools/{username}')
    return jsonify({'success': True, 'message': 'Đã xóa'})

@admin_bp.route('/api/create_key', methods=['POST'])
def create_key():
    if not session.get('admin_authenticated'):
        return jsonify({'success': False, 'error': 'Unauthorized'})
    data = request.json
    tool_name = data.get('tool_name')
    is_lifetime = data.get('is_lifetime', False)
    expiry = data.get('expiry')
    key_code = "KEY-" + str(uuid.uuid4())[:8].upper() + "-" + str(int(datetime.now().timestamp()) % 10000)
    key_data = {
        'tool_name': tool_name,
        'is_lifetime': is_lifetime,
        'expiry': expiry,
        'is_used': False,
        'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    FirebaseHelper.set(f'/keys/{key_code}', key_data)
    return jsonify({'success': True, 'key': key_code})

@admin_bp.route('/api/get_keys', methods=['GET'])
def get_keys():
    if not session.get('admin_authenticated'):
        return jsonify({'success': False, 'error': 'Unauthorized'})
    keys = FirebaseHelper.get('/keys') or {}
    return jsonify({'success': True, 'keys': keys})

@admin_bp.route('/api/delete_key', methods=['POST'])
def delete_key():
    if not session.get('admin_authenticated'):
        return jsonify({'success': False, 'error': 'Unauthorized'})
    key_code = request.json.get('key_code')
    FirebaseHelper.delete(f'/keys/{key_code}')
    return jsonify({'success': True, 'message': 'Đã xóa key'})
