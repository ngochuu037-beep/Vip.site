# utils.py
import hashlib
import base64
import json
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import requests

def decode_nickname(encoded: str, secret_key: bytes) -> str:
    try:
        raw = base64.b64decode(encoded)
        dec = bytearray()
        for i, b in enumerate(raw):
            dec.append(b ^ secret_key[i % len(secret_key)])
        return dec.decode("utf-8", errors="replace")
    except Exception:
        return encoded

def aes_encrypt(data: bytes, key, iv) -> bytes:
    if isinstance(key, str):
        key = bytes.fromhex(key) if len(key) == 32 else key.encode()
    if isinstance(iv, str):
        iv = bytes.fromhex(iv) if len(iv) == 32 else iv.encode()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, AES.block_size))

def aes_decrypt(data: bytes, key, iv) -> bytes:
    if isinstance(key, str):
        key = bytes.fromhex(key) if len(key) == 32 else key.encode()
    if isinstance(iv, str):
        iv = bytes.fromhex(iv) if len(iv) == 32 else iv.encode()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data), AES.block_size)

def parse_proto(data: bytes) -> dict:
    result = {}
    idx = 0
    while idx < len(data):
        try:
            tag = data[idx]
            idx += 1
            fn = tag >> 3
            wt = tag & 0x07
            if wt == 0:
                val = 0
                shift = 0
                while idx < len(data):
                    b = data[idx]
                    idx += 1
                    val |= (b & 0x7F) << shift
                    if not (b & 0x80):
                        break
                    shift += 7
                if fn in result:
                    if not isinstance(result[fn], list):
                        result[fn] = [result[fn]]
                    result[fn].append(val)
                else:
                    result[fn] = val
            elif wt == 2:
                length = 0
                shift = 0
                while idx < len(data):
                    b = data[idx]
                    idx += 1
                    length |= (b & 0x7F) << shift
                    if not (b & 0x80):
                        break
                    shift += 7
                value_bytes = data[idx:idx+length]
                idx += length
                try:
                    result[fn] = value_bytes.decode('utf-8')
                except:
                    result[fn] = value_bytes.hex()
            elif wt == 1:
                idx += 8
            elif wt == 5:
                idx += 4
            else:
                break
        except:
            break
    return result

def decode_jwt(token: str, secret_key: bytes) -> dict:
    parts = token.split('.')
    if len(parts) < 2:
        return {}
    payload_b64 = parts[1]
    # padding
    payload_b64 += '=' * (-len(payload_b64) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode())
        if "nickname" in payload and isinstance(payload["nickname"], str):
            payload["nickname"] = decode_nickname(payload["nickname"], secret_key)
        return payload
    except:
        return {}

def convert_time(seconds: int) -> str:
    d, s = divmod(int(seconds), 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    return f"{d}d {h}h {m}m {s}s"

def parse_duration(duration_str: str) -> int:
    total = 0
    parts = duration_str.split(':')
    for part in parts:
        part = part.strip().lower()
        if not part:
            continue
        if part.endswith('d'):
            total += int(part[:-1]) * 86400
        elif part.endswith('h'):
            total += int(part[:-1]) * 3600
        elif part.endswith('m'):
            total += int(part[:-1]) * 60
        elif part.endswith('s'):
            total += int(part[:-1])
        elif part.isdigit():
            total += int(part)
    return total

def extract_eat_from_input(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith('http'):
        m = re.search(r'[?&]eat=([a-fA-F0-9]+)', raw)
        if m:
            return m.group(1)
    return raw

def eat_to_access(eat_token: str) -> str:
    TARGET = "https://api-otrss.garena.com/support/callback/"
    session = requests.Session()
    resp = session.get(TARGET, params={'access_token': eat_token}, allow_redirects=False)
    while resp.status_code in (301, 302, 303, 307, 308):
        location = resp.headers.get('Location', '')
        if not location:
            break
        if not location.startswith(('http://', 'https://')):
            base = urlparse(TARGET)
            location = base._replace(path=location).geturl()
        resp = session.get(location, allow_redirects=False)
    parsed = urlparse(resp.url)
    params = parse_qs(parsed.query)
    return params.get('access_token', [None])[0]

def _varint(v):
    result = bytearray()
    while v > 0x7F:
        result.append((v & 0x7F) | 0x80)
        v >>= 7
    result.append(v)
    return bytes(result)

def _int_field(f, v):
    return _varint((f << 3) | 0) + _varint(v)

def _str_field(f, v):
    if isinstance(v, str):
        v = v.encode()
    return _varint((f << 3) | 2) + _varint(len(v)) + v
