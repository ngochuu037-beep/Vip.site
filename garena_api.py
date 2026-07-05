# garena_api.py
import requests
import hashlib
import time
from datetime import datetime
from utils import aes_encrypt, parse_proto, _str_field, _int_field, decode_jwt
from config import Config
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

GARENA_HEADERS = {
    "User-Agent": "GarenaMSDK/4.0.19P9(Redmi Note 5 ;Android 9;en;US;)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip"
}

def inspect_token(access_token: str):
    url = f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}"
    headers = {"Connection": "close", "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)"}
    resp = requests.get(url, headers=headers, timeout=10)
    data = resp.json()
    if 'error' in data:
        err = data.get('error')
        if err == "invalid_request":
            raise Exception("Token đã hết hạn hoặc không tồn tại hoặc tài khoản bị ban")
        raise Exception(f"Token lỗi: {err}")
    return data.get('open_id'), int(data.get('platform', 8))

def build_login_payload(open_id: str, access_token: str, platform: int) -> bytes:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    payload = bytearray()
    payload += _str_field(3, now)
    payload += _str_field(22, open_id)
    payload += _str_field(23, str(platform))
    payload += _str_field(29, access_token)
    payload += _str_field(99, str(platform))
    return bytes(payload)

def do_major_login(open_id: str, access_token: str, platform: int):
    url = "https://loginbp.ggpolarbear.com/MajorLogin"
    headers = {
        'X-Unity-Version': '2018.4.11f1',
        'ReleaseVersion': "OB53",
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-GA': 'v1 1',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
        'Host': 'loginbp.ggpolarbear.com',
        'Connection': 'Keep-Alive'
    }
    enc = aes_encrypt(build_login_payload(open_id, access_token, platform), Config.AES_KEY, Config.AES_IV)
    resp = requests.post(url, headers=headers, data=enc, verify=False, timeout=10)
    if resp.status_code != 200:
        raise Exception(f"MajorLogin thất bại HTTP {resp.status_code}")

    content = resp.content
    # Thử parse trực tiếp
    try:
        import MajorLogin_res_pb2
        res = MajorLogin_res_pb2.MajorLoginRes()
        try:
            res.ParseFromString(content)
            token = res.account_jwt or getattr(res, 'token', None)
            if token:
                return token, res.key, res.iv
        except:
            pass
        # Thử giải mã AES
        try:
            dec = aes_decrypt(content, Config.AES_KEY, Config.AES_IV)
            res.ParseFromString(dec)
            token = res.account_jwt or getattr(res, 'token', None)
            if token:
                return token, res.key, res.iv
        except:
            pass
    except:
        pass

    # Fallback parse_proto
    parsed = parse_proto(content)
    token = parsed.get(8)
    if isinstance(token, list):
        token = token[0]
    if token:
        if isinstance(token, bytes):
            token = token.decode('utf-8', 'ignore')
        key = parsed.get(22, Config.AES_KEY)
        if isinstance(key, list):
            key = key[0]
        iv = parsed.get(23, Config.AES_IV)
        if isinstance(iv, list):
            iv = iv[0]
        return token, key, iv

    raise Exception("Không parse được JWT từ MajorLogin")

def get_available_room(hex_data: str) -> dict:
    """Trích xuất địa chỉ server từ GetLoginData response"""
    try:
        data = bytes.fromhex(hex_data)
        result = {}
        index = 0
        while index < len(data):
            tag = data[index]
            field_num = tag >> 3
            wire_type = tag & 0x07
            index += 1
            if wire_type == 0:
                value, index = decode_varint(data, index)
                result[str(field_num)] = {"data": value}
            elif wire_type == 2:
                length, index = decode_varint(data, index)
                if index + length <= len(data):
                    value_bytes = data[index:index+length]
                    index += length
                    try:
                        value_str = value_bytes.decode('utf-8')
                        result[str(field_num)] = {"data": value_str}
                    except:
                        result[str(field_num)] = {"data": value_bytes.hex()}
            else:
                break
        return result
    except:
        return {}

def decode_varint(data, start):
    value = 0
    shift = 0
    i = start
    while i < len(data):
        b = data[i]
        i += 1
        value |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return value, i

def guest_get_access(uid, password):
    url = "https://100067.connect.garena.com/oauth/token"
    data = {
        'grant_type': 'password',
        'app_id': '100067',
        'account': uid,
        'password': hashlib.md5(password.encode()).hexdigest()
    }
    headers = {
        'User-Agent': 'GarenaMSDK/4.0.19P9(Redmi Note 5 ;Android 9;en;US;)',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    try:
        r = requests.post(url, data=data, headers=headers, timeout=12)
        j = r.json()
        return j.get('open_id'), j.get('access_token')
    except:
        return None, None

def send_otp(email, access_token):
    url = "https://100067.connect.garena.com/game/account_security/bind:send_otp"
    data = {"email": email, "locale": "en_MA", "region": "IND",
            "app_id": "100067", "access_token": access_token}
    try:
        return requests.post(url, headers=GARENA_HEADERS, data=data)
    except:
        return None

def verify_otp(otp, email, access_token):
    url = "https://100067.connect.garena.com/game/account_security/bind:verify_otp"
    data = {"app_id": "100067", "access_token": access_token, "otp": otp, "email": email}
    return requests.post(url, data=data, headers=GARENA_HEADERS)

def cancel_request(access_token):
    url = "https://100067.connect.garena.com/game/account_security/bind:cancel_request"
    payload = {'app_id': "100067", 'access_token': access_token}
    try:
        requests.post(url, data=payload, headers=GARENA_HEADERS)
    except:
        pass
