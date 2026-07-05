# spam_log.py
import threading
import time
import socket
import json
import os
from config import Config
from utils import parse_proto
from garena_api import inspect_token, do_major_login, build_login_payload, aes_encrypt
from utils import _str_field, _int_field
from datetime import datetime
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

active_spams = {}  # username -> { ... }
spam_lock = threading.Lock()
SPAM_CACHE_FILE = Config.SPAM_CACHE_FILE

def load_spam_cache():
    if os.path.exists(SPAM_CACHE_FILE):
        try:
            with open(SPAM_CACHE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_spam_cache(data):
    clean_data = {}
    for k, v in data.items():
        clean_data[str(k)] = {
            'at': v.get('at'),
            'status': v.get('status'),
            'sent': v.get('sent', 0),
            'ok': v.get('ok', 0),
            'fail': v.get('fail', 0),
            'ip': v.get('ip'),
            'port': v.get('port'),
            'end_time': v.get('end_time'),
            'packet': v.get('packet').hex() if isinstance(v.get('packet'), bytes) else v.get('packet'),
            'interval': v.get('interval'),
            'total_ms': v.get('total_ms')
        }
    with open(SPAM_CACHE_FILE, 'w', encoding='utf-8') as f:
        json.dump(clean_data, f, ensure_ascii=False, indent=2)

def spam_loop(username, ip, port, packet, interval_ms, end_time, stop_event):
    while time.time() < end_time:
        if stop_event.is_set():
            break
        try:
            send_packet_tcp(ip, port, packet, timeout=5)
            with spam_lock:
                if username in active_spams:
                    active_spams[username]['ok'] += 1
        except:
            with spam_lock:
                if username in active_spams:
                    active_spams[username]['fail'] += 1
        with spam_lock:
            if username in active_spams:
                active_spams[username]['sent'] += 1
        time.sleep(interval_ms / 1000.0)
    with spam_lock:
        if username in active_spams:
            active_spams[username]['status'] = 'finished'
            save_spam_cache(active_spams)

def send_packet_tcp(ip, port, packet, timeout=5):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(packet)

def build_final_packet(jwt_token, key, iv):
    # Tương tự như trong app.py cũ
    import base64
    import json
    from utils import decode_jwt
    payload = decode_jwt(jwt_token, Config.SECRET_KEY_BYTES)
    acc_id = int(payload.get('account_id', 0))
    exp = int(payload.get('exp', 0))
    exp_adj = max(exp - 28800, 0)
    enc_token = aes_encrypt(jwt_token.encode(), key, iv)
    body_len = len(enc_token)
    header = bytes.fromhex(
        "0115" +
        acc_id.to_bytes(8, "big").hex() +
        exp_adj.to_bytes(4, "big").hex() +
        body_len.to_bytes(4, "big").hex()
    )
    return header + enc_token

def start_spam_log(username, access_token, interval_ms, duration_ms, stop_event):
    try:
        open_id, platform = inspect_token(access_token)
        # Thử các platform
        jwt_token = None
        m_key, m_iv = None, None
        platforms_to_try = [platform] + [p for p in [2,3,4,6,8] if p != platform]
        for pt in platforms_to_try:
            try:
                token, key, iv = do_major_login(open_id, access_token, pt)
                if token:
                    jwt_token = token
                    m_key, m_iv = key, iv
                    break
            except:
                continue
        if not jwt_token:
            raise Exception("Không thể lấy JWT token")

        # GetLoginData để lấy server
        enc = aes_encrypt(build_login_payload(open_id, access_token, platform), Config.AES_KEY, Config.AES_IV)
        headers = {
            'Authorization': f'Bearer {jwt_token}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': "OB53",
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
            'Host': 'clientbp.ggpolarbear.com',
            'Connection': 'close'
        }
        resp = requests.post("https://clientbp.ggpolarbear.com/GetLoginData",
                             headers=headers, data=enc, verify=False, timeout=10)
        room_info = get_available_room(resp.content.hex())
        addr = room_info.get('14', {}).get('data')
        if not addr:
            raise Exception("Không tìm thấy địa chỉ server")
        online_ip = addr[:-6]
        online_port = int(addr[-5:])

        # Tạo packet cuối
        final_packet = build_final_packet(jwt_token, m_key, m_iv)

        end_time = time.time() + (duration_ms / 1000.0)
        with spam_lock:
            active_spams[username] = {
                'at': access_token,
                'stop_event': stop_event,
                'status': 'running',
                'sent': 0,
                'ok': 0,
                'fail': 0,
                'ip': online_ip,
                'port': online_port,
                'end_time': end_time,
                'packet': final_packet,
                'interval': interval_ms,
                'total_ms': duration_ms
            }
            save_spam_cache(active_spams)

        # Chạy luồng spam
        thread = threading.Thread(
            target=spam_loop,
            args=(username, online_ip, online_port, final_packet, interval_ms, end_time, stop_event)
        )
        thread.daemon = True
        thread.start()
        return True, None
    except Exception as e:
        return False, str(e)

def get_spam_status(username):
    with spam_lock:
        if username in active_spams:
            return active_spams[username]
        # Kiểm tra cache
        cache = load_spam_cache()
        if str(username) in cache:
            return cache[str(username)]
    return None
