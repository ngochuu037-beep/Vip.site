# app.py
from flask import Flask, render_template, session, request
from config import Config
from auth_routes import auth_bp
from tool_routes import tools_bp
from admin_routes import admin_bp
import os

app = Flask(__name__)
app.secret_key = Config.SECRET_KEY

# Đăng ký Blueprint
app.register_blueprint(auth_bp)
app.register_blueprint(tools_bp)
app.register_blueprint(admin_bp)

# Routes trang HTML
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/auth')
def auth_page():
    return render_template('auth.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/tools')
def tools_page():
    return render_template('tools.html')

@app.route('/dashboard')
def dashboard():
    if not session.get('admin_authenticated'):
        return redirect('/admin/login')
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
