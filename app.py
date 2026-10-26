import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import DES, DES3

app = Flask(__name__)
CORS(app) # Permite peticiones desde astralchk.com

# Variables de entorno (las configuras en Northflank)
API_KEY = os.environ.get('CVV_API_KEY', None)
DEFAULT_CVKA = os.environ.get('CVK_A', None)
DEFAULT_CVKB = os.environ.get('CVK_B', None)

# ============================================================
# LÓGICA MATEMÁTICA (Tu script exacto)
# ============================================================
def _hex_xor(a: str, b: str) -> str:
    int_a = int(a, 16)
    int_b = int(b, 16)
    return format(int_a ^ int_b, '016X')

def _des_encrypt_block(key_hex: str, data_hex: str) -> str:
    key  = bytes.fromhex(key_hex)
    data = bytes.fromhex(data_hex)
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data).hex().upper()

def _3des_encrypt_block(key_hex: str, data_hex: str) -> str:
    key  = bytes.fromhex(key_hex)
    data = bytes.fromhex(data_hex)
    cipher = DES3.new(key, DES3.MODE_ECB)
    return cipher.encrypt(data).hex().upper()

def _decimalize(hex_str: str) -> str:
    mapping = {'A': '0', 'B': '1', 'C': '2', 'D': '3', 'E': '4', 'F': '5'}
    result = ''
    for ch in hex_str.upper():
        if '0' <= ch <= '9':
            result += ch
    for ch in hex_str.upper():
        if ch in mapping:
            result += mapping[ch]
    return result

def calculate_cvv(pan: str, expdate: str, service_code: str, cvka: str, cvkb: str) -> str:
    pan_norm = pan.strip().replace(' ', '').replace('|', '')
    pan_norm = pan_norm.zfill(16)[-16:]

    expdate_clean = expdate.replace('/', '').strip()
    data_block = (expdate_clean + service_code).ljust(16, '0')

    cvka_u = cvka.upper().strip()
    cvkb_u = cvkb.upper().strip()

    step1 = _des_encrypt_block(cvka_u, pan_norm)
    step2 = _hex_xor(step1, data_block)
    step3 = _3des_encrypt_block(cvka_u + cvkb_u, step2)

    return _decimalize(step3)[:3]

# ============================================================
# RUTAS DE LA API
# ============================================================
@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "OK", "ts": "now"})

@app.route('/api/calculate-cvv', methods=['POST'])
def api_calculate_cvv():
    # Auth opcional
    if API_KEY:
        provided = request.headers.get('X-API-Key') or request.args.get('api_key')
        if provided != API_KEY:
            return jsonify({"success": False, "error": "Unauthorized"}), 401

    data = request.json or {}
    
    pan = data.get('pan')
    expdate = data.get('expdate')
    service_code = data.get('service_code', data.get('serviceCode', '000'))
    cvka = data.get('cvka') or DEFAULT_CVKA
    cvkb = data.get('cvkb') or DEFAULT_CVKB

    if not pan or not expdate:
        return jsonify({"success": False, "error": "pan and expdate are required"}), 400
        
    if not cvka or not cvkb:
        return jsonify({"success": False, "error": "cvka/cvkb required (body or env)"}), 400

    try:
        cvv = calculate_cvv(pan, expdate, service_code, cvka, cvkb)
        return jsonify({"success": True, "cvv": cvv})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=port)