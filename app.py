from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from crypto_algorithms import *
from crypto_algorithms import aes_encrypt, aes_decrypt
import math

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

received_message = ""


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
        des_key = key[:8] if key else "12345678"
        encrypted = des_encrypt(message, des_key)

    elif algo == "AES":
        encrypted = aes_encrypt(message, key)

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
        des_key = key[:8] if key else "12345678"
        decrypted = des_decrypt(received_message, des_key)

    elif algo == "AES":
        decrypted = aes_decrypt(received_message, key)

    else:
        decrypted = received_message

    emit('receive_decrypted', {'decrypted': decrypted}, broadcast=True)


if __name__ == '__main__':
    socketio.run(app, debug=True)
