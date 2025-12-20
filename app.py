from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from crypto_algorithms import *
from crypto_algorithms import aes_encrypt, aes_decrypt
import math

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

received_message = ""

# RSA keypair (server)
SERVER_RSA_PUBLIC, SERVER_RSA_PRIVATE = rsa_generate_keypair(2048)

# (Optional) session keys distributed via RSA
SESSION_AES_KEY = None
SESSION_DES_KEY = None


def parse_hill_key(key_string):
    """
    Hill Cipher anahtarını string'den matrise çevirir.
    Format: "a,b,c,d" veya "a,b,c,d,e,f,g,h,i" (2x2 veya 3x3)
    """
    try:
        numbers = [int(x.strip()) % 26 for x in key_string.split(',')]
        n = int(math.sqrt(len(numbers)))
        if n * n != len(numbers):
            raise ValueError("Anahtar matrisi kare olmalı (4 veya 9 eleman)")
        return [[numbers[i * n + j] for j in range(n)] for i in range(n)]
    except:
        return [[3, 3], [2, 5]]


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/client')
def client_page():
    return render_template('client.html')


@app.route('/server')
def server_page():
    return render_template('server.html', message=received_message)


# ================= SOCKET EVENTS =================

@socketio.on('get_rsa_public_key')
def get_rsa_public_key():
    emit('rsa_public_key', {'public_key': SERVER_RSA_PUBLIC})


@socketio.on('exchange_session_key')
def exchange_session_key(data):
    global SESSION_AES_KEY, SESSION_DES_KEY
    algo = data.get('algo')
    encrypted_key = data.get('encrypted_key', '')
    try:
        key_plain = rsa_decrypt_text(SERVER_RSA_PRIVATE, encrypted_key)
    except Exception:
        emit('key_exchange_ok', {'ok': False, 'algo': algo})
        return

    if algo == "AES":
        # AES tarafında biz zaten string key'den 16 byte türetiyoruz, burada string saklıyoruz
        SESSION_AES_KEY = key_plain
    elif algo == "DES":
        SESSION_DES_KEY = key_plain[:8]

    emit('key_exchange_ok', {'ok': True, 'algo': algo})


@socketio.on('send_message')
def handle_send_message(data):
    global received_message

    message = data['message']
    algo = data['algo']
    key = data.get('key', '')

    if algo == "Caesar":
        encrypted = caesar_encrypt(message)

    elif algo == "Vigenere":
        encrypted = vigenere_encrypt(message, key)

    elif algo == "Substitution":
        encrypted = substitution_encrypt(message, key)

    elif algo == "Affine":
        encrypted = affine_encrypt(message)

    elif algo == "Rail Fence":
        rails = int(key) if key.isdigit() and int(key) >= 2 else 3
        encrypted = rail_fence_encrypt(message, rails)

    elif algo == "Route Cipher":
        width = int(key) if key.isdigit() and int(key) >= 2 else 5
        encrypted = route_encrypt(message, width=width)

    elif algo == "Columnar Transposition":
        encrypted = columnar_encrypt(message, key if key else "truva")

    elif algo == "Polybius":
        encrypted = polybius_encrypt(message)

    elif algo == "Pigpen":
        encrypted = pigpen_encrypt(message)

    elif algo == "Hill":
        key_matrix = parse_hill_key(key) if key else [[3, 3], [2, 5]]
        encrypted = hill_encrypt(message, key_matrix)

    elif algo == "DES":
        des_key = (key or SESSION_DES_KEY or "12345678")[:8]
        encrypted = des_encrypt(message, des_key)

    elif algo == "DES (Library)":
        des_key = (key or SESSION_DES_KEY or "12345678")[:8]
        encrypted = des_lib_encrypt(message, des_key)

    elif algo == "AES":
        aes_key = key or SESSION_AES_KEY or ""
        encrypted = aes_encrypt(message, aes_key)

    elif algo == "RSA":
        # Kütüphaneli mod: RSA ile mesaj şifreleme (demo)
        encrypted = rsa_encrypt_text(SERVER_RSA_PUBLIC, message)

    else:
        encrypted = message

    received_message = encrypted
    emit('receive_message', {'message': encrypted}, broadcast=True)


@socketio.on('decrypt_message')
def handle_decrypt_message(data):
    global received_message

    algo = data['algo']
    key = data.get('key', '')

    if algo == "Caesar":
        decrypted = caesar_decrypt(received_message)

    elif algo == "Vigenere":
        decrypted = vigenere_decrypt(received_message, key)

    elif algo == "Substitution":
        decrypted = substitution_decrypt(received_message, key)

    elif algo == "Affine":
        decrypted = affine_decrypt(received_message)

    elif algo == "Rail Fence":
        rails = int(key) if key.isdigit() and int(key) >= 2 else 3
        decrypted = rail_fence_decrypt(received_message, rails)

    elif algo == "Route Cipher":
        width = int(key) if key.isdigit() and int(key) >= 2 else 5
        decrypted = route_decrypt(received_message, width=width)

    elif algo == "Columnar Transposition":
        decrypted = columnar_decrypt(received_message, key if key else "truva")

    elif algo == "Polybius":
        decrypted = polybius_decrypt(received_message)

    elif algo == "Pigpen":
        decrypted = pigpen_decrypt(received_message)

    elif algo == "Hill":
        key_matrix = parse_hill_key(key) if key else [[3, 3], [2, 5]]
        decrypted = hill_decrypt(received_message, key_matrix)

    elif algo == "DES":
        des_key = (key or SESSION_DES_KEY or "12345678")[:8]
        decrypted = des_decrypt(received_message, des_key)

    elif algo == "DES (Library)":
        des_key = (key or SESSION_DES_KEY or "12345678")[:8]
        decrypted = des_lib_decrypt(received_message, des_key)

    elif algo == "AES":
        aes_key = key or SESSION_AES_KEY or ""
        decrypted = aes_decrypt(received_message, aes_key)

    elif algo == "RSA":
        decrypted = rsa_decrypt_text(SERVER_RSA_PRIVATE, received_message)

    else:
        decrypted = received_message

    emit('receive_decrypted', {'decrypted': decrypted}, broadcast=True)


if __name__ == '__main__':
    socketio.run(app, debug=True)
