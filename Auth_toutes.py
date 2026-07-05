# auth_routes.py
from flask import Blueprint, request, jsonify, session, make_response
import hashlib
import uuid
from datetime import datetime, timedelta
from firebase_helper import FirebaseHelper
import re

auth_bp = Blueprint('auth', __name__, url_prefix='/api')

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    if not all([username, email, password]):
        return jsonify({'success': False, 'error': 'Thiếu thông tin'})
    if len(username) < 3 or len(username) > 20:
        return jsonify({'success': False, 'error': 'Tên đăng nhập 3-20 ký tự'})
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return jsonify({'success': False, 'error': 'Email không hợp lệ'})
    if len(password) < 6:
        return jsonify({'success': False, 'error': 'Mật khẩu phải có ít nhất 6 ký tự'})

    users = FirebaseHelper.get('/users') or {}
    if username in users:
        return jsonify({'success': False, 'error': 'Tên đăng nhập đã tồn tại'})
    for u in users.values():
        if u.get('email') == email:
            return jsonify({'success': False, 'error': 'Email đã được sử dụng'})

    hashed = hashlib.sha256(password.encode()).hexdigest()
    user_data = {
        'username': username,
        'email': email,
        'password': hashed,
        'created_at': datetime.now().isoformat(),
        'is_pro': False
    }
    FirebaseHelper.set(f'/users/{username}', user_data)
    FirebaseHelper.set(f'/usage/{username}', {'ban7': 0, 'spam_log': 0, 'is_pro': False})
    return jsonify({'success': True, 'message': 'Đăng ký thành công'})

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    login_input = data.get('username')
    password = data.get('password')
    remember_me = data.get('remember_me', False)
    if not login_input or not password:
        return jsonify({'success': False, 'error': 'Thiếu thông tin'})
    hashed = hashlib.sha256(password.encode()).hexdigest()
    users = FirebaseHelper.get('/users') or {}
    user = None
    username = None
    for u_name, u_data in users.items():
        if u_name == login_input or u_data.get('email') == login_input:
            user = u_data
            username = u_name
            break
    if not user or user.get('password') != hashed:
        return jsonify({'success': False, 'error': 'Sai tên đăng nhập hoặc mật khẩu'})

    session['username'] = username
    session['authenticated'] = True
    session['email'] = user.get('email')
    response = jsonify({'success': True, 'message': 'Đăng nhập thành công'})
    if remember_me:
        remember_token = str(uuid.uuid4())
        FirebaseHelper.update(f'/users/{username}', {'remember_token': remember_token})
        expires = datetime.now() + timedelta(days=30)
        response.set_cookie('remember_token', remember_token, expires=expires, httponly=True, samesite='Lax')
    return response

@auth_bp.route('/logout', methods=['POST'])
def logout():
    username = session.get('username')
    if username:
        FirebaseHelper.update(f'/users/{username}', {'remember_token': None})
    session.clear()
    response = jsonify({'success': True, 'message': 'Đăng xuất thành công'})
    response.set_cookie('remember_token', '', expires=0)
    return response

@auth_bp.route('/check_auth', methods=['GET'])
def check_auth():
    if session.get('authenticated') and session.get('username'):
        username = session.get('username')
        usage = FirebaseHelper.get(f'/usage/{username}') or {'ban7': 0, 'spam_log': 0, 'is_pro': False}
        user = FirebaseHelper.get(f'/users/{username}') or {}
        # Kiểm tra pro từ key
        from tool_routes import check_tool_pro
        usage['ban7_pro'] = check_tool_pro(username, 'ban7')
        usage['spam_log_pro'] = check_tool_pro(username, 'spam_log')
        return jsonify({
            'authenticated': True,
            'username': username,
            'email': user.get('email', ''),
            'usage': usage
        })
    # Cookie remember
    remember_token = request.cookies.get('remember_token')
    if remember_token:
        users = FirebaseHelper.get('/users') or {}
        for uname, u_data in users.items():
            if u_data.get('remember_token') == remember_token:
                session['username'] = uname
                session['authenticated'] = True
                session['email'] = u_data.get('email')
                usage = FirebaseHelper.get(f'/usage/{uname}') or {'ban7': 0, 'spam_log': 0, 'is_pro': False}
                usage['ban7_pro'] = check_tool_pro(uname, 'ban7')
                usage['spam_log_pro'] = check_tool_pro(uname, 'spam_log')
                return jsonify({
                    'authenticated': True,
                    'username': uname,
                    'email': u_data.get('email', ''),
                    'usage': usage
                })
    return jsonify({'authenticated': False})
