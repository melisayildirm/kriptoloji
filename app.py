from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from crypto_algorithms import *
import math
import ast
import base64  # (kalsın, başka yerde kullanıyor olabilirsin)
from crypto_algorithms import (
    aes_user_encrypt, aes_user_decrypt,
    aes_lib_encrypt, aes_lib_decrypt,
    aes_manual_encrypt, aes_manual_decrypt,
    des_encrypt, des_decrypt,
    des_lib_encrypt, des_lib_decrypt,
    rsa_generate_keypair, rsa_encrypt_text, rsa_decrypt_text,
    hill_encrypt, hill_decrypt
)

aes_encrypt = aes_user_encrypt
aes_decrypt = aes_user_decrypt

RSA_PUBLIC_KEY, RSA_PRIVATE_KEY = rsa_generate_keypair()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

received_message = ""

# RSA keypair (server)
SERVER_RSA_PUBLIC, SERVER_RSA_PRIVATE = rsa_generate_keypair(2048)

# Session keys distributed via RSA (Library modlar için)
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
def handle_exchange_session_key(data):
    """İstemciden RSA ile şifrelenmiş oturum anahtarını alır ve server tarafında saklar."""
    global SESSION_AES_KEY, SESSION_DES_KEY
    try:
        algorithm = data.get('algorithm') or data.get('algo')
        encrypted_key_b64 = data.get('encrypted_key')

        if not algorithm or not encrypted_key_b64:
            raise ValueError("exchange_session_key verisi eksik (algorithm/encrypted_key).")

        # ✅ Client artık base64 değil, direkt ASCII key string gönderiyor (DES=8, AES=16)
        key_text = rsa_decrypt_text(SERVER_RSA_PRIVATE, encrypted_key_b64)

        if isinstance(key_text, (bytes, bytearray)):
            key_bytes = bytes(key_text)
        else:
            key_bytes = str(key_text).encode("utf-8")

        if algorithm == 'AES (Library)':
            if len(key_bytes) != 16:
                raise ValueError('AES (Library) anahtarı 16 byte olmalıdır.')
            SESSION_AES_KEY = key_bytes

        elif algorithm == 'DES (Library)':
            if len(key_bytes) != 8:
                raise ValueError('DES (Library) anahtarı 8 byte olmalıdır.')
            SESSION_DES_KEY = key_bytes

        else:
            raise ValueError('Bilinmeyen algoritma için oturum anahtarı gönderildi.')

        # Client tarafı key_exchange_ok dinliyor
        socketio.emit('key_exchange_ok', {'ok': True, 'algorithm': algorithm})

    except Exception as e:
        socketio.emit('error', {'message': f'Oturum anahtarı değişimi hatası: {str(e)}'})
        socketio.emit('key_exchange_ok', {'ok': False, 'message': str(e)})


@socketio.on('send_message')
def handle_send_message(data):
    global received_message
    try:
        message = data.get('message', '')
        algorithm = data.get('algorithm') or data.get('algo')
        key = data.get('key')

        if not algorithm:
            raise ValueError("Algoritma seçimi yok.")

        # Manuel / klasik şifreler
        if algorithm == 'Caesar':
            if key is None or key == '':
                raise ValueError('Caesar için anahtar (kaydırma sayısı) zorunludur.')
            encrypted = caesar_encrypt(message, int(key))

        elif algorithm == 'Vigenere':
            if not key:
                raise ValueError('Vigenere için anahtar kelime zorunludur.')
            encrypted = vigenere_encrypt(message, key)

        elif algorithm == 'Substitution':
            if not key:
                raise ValueError('Substitution için anahtar kelime zorunludur.')
            encrypted = substitution_encrypt(message, key)

        elif algorithm == 'Affine':
            if not key:
                raise ValueError('Affine için anahtar zorunludur. Örn: 5,8')
            a, b = map(int, key.split(','))
            encrypted = affine_encrypt(message, a, b)

        elif algorithm == 'Rail Fence':
            if not key:
                raise ValueError('Rail Fence için ray sayısı zorunludur.')
            encrypted = rail_fence_encrypt(message, int(key))

        elif algorithm == 'Route Cipher':
            if not key:
                raise ValueError('Route Cipher için anahtar zorunludur.')
            encrypted = route_encrypt(message, key)

        elif algorithm == 'Columnar Transposition':
            if not key:
                raise ValueError('Columnar Transposition için anahtar zorunludur.')
            encrypted = columnar_encrypt(message, key)

        elif algorithm == 'Polybius':
            if not key:
                raise ValueError('Polybius için anahtar zorunludur.')
            encrypted = polybius_encrypt(message, key)

        elif algorithm == 'Pigpen':
            encrypted = pigpen_encrypt(message)

        elif algorithm == 'Hill':
            if not key:
                raise ValueError('Hill için anahtar matrisi zorunludur. Örn: [2,2,3,3]')
            key_matrix = ast.literal_eval(key)
            encrypted = hill_encrypt(message, key_matrix)

        # --- DES / AES MODLARI ---
        elif algorithm == 'DES (Manual)':
            if not key:
                raise ValueError('DES (Manual) için 8 byte anahtar zorunludur.')
            encrypted = des_encrypt(message, key)

        elif algorithm == 'DES (Library)':
            if SESSION_DES_KEY is None:
                raise ValueError('DES (Library) için önce RSA ile oturum anahtarı değişimi yapılmalı.')
            encrypted = des_lib_encrypt(message, SESSION_DES_KEY)

        elif algorithm == 'AES (Manual)':
            if not key:
                raise ValueError('AES (Manual) için 16 byte anahtar zorunludur.')
            encrypted = aes_manual_encrypt(message, key)

        elif algorithm == 'AES (Library)':
            if SESSION_AES_KEY is None:
                raise ValueError('AES (Library) için önce RSA ile oturum anahtarı değişimi yapılmalı.')
            encrypted = aes_lib_encrypt(message, SESSION_AES_KEY)

        elif algorithm == 'RSA':
            if not RSA_PUBLIC_KEY or not RSA_PRIVATE_KEY:
                raise ValueError('RSA anahtarları bulunamadı.')
            encrypted = rsa_encrypt_text(RSA_PUBLIC_KEY, message)

        else:
            raise ValueError('Geçersiz algoritma seçimi.')

        # Sunucu sayfasında görünmesi için sakla
        received_message = encrypted

        # Client’a bilgi
        socketio.emit('message_sent', {'algorithm': algorithm})

        # Server ekranına düşür
        socketio.emit('receive_message', {'message': encrypted, 'algorithm': algorithm})

    except Exception as e:
        socketio.emit('error', {'message': str(e)})


@socketio.on('decrypt_message')
def handle_decrypt_message(data):
    try:
        encrypted_message = data.get('message', '')
        algorithm = data.get('algorithm') or data.get('algo')
        key = data.get('key')

        if not algorithm:
            raise ValueError("Algoritma seçimi yok.")
        if not encrypted_message:
            raise ValueError("Şifreli mesaj boş.")

        if algorithm == 'Caesar':
            if key is None or key == '':
                raise ValueError('Caesar için anahtar zorunludur.')
            decrypted = caesar_decrypt(encrypted_message, int(key))

        elif algorithm == 'Vigenere':
            if not key:
                raise ValueError('Vigenere için anahtar zorunludur.')
            decrypted = vigenere_decrypt(encrypted_message, key)

        elif algorithm == 'Substitution':
            if not key:
                raise ValueError('Substitution için anahtar zorunludur.')
            decrypted = substitution_decrypt(encrypted_message, key)

        elif algorithm == 'Affine':
            if not key:
                raise ValueError('Affine için anahtar zorunludur. Örn: 5,8')
            a, b = map(int, key.split(','))
            decrypted = affine_decrypt(encrypted_message, a, b)

        elif algorithm == 'Rail Fence':
            if not key:
                raise ValueError('Rail Fence için anahtar zorunludur.')
            decrypted = rail_fence_decrypt(encrypted_message, int(key))

        elif algorithm == 'Route Cipher':
            if not key:
                raise ValueError('Route Cipher için anahtar zorunludur.')
            decrypted = route_decrypt(encrypted_message, key)

        elif algorithm == 'Columnar Transposition':
            if not key:
                raise ValueError('Columnar Transposition için anahtar zorunludur.')
            decrypted = columnar_decrypt(encrypted_message, key)

        elif algorithm == 'Polybius':
            if not key:
                raise ValueError('Polybius için anahtar zorunludur.')
            decrypted = polybius_decrypt(encrypted_message, key)

        elif algorithm == 'Pigpen':
            decrypted = pigpen_decrypt(encrypted_message)

        elif algorithm == 'Hill':
            if not key:
                raise ValueError('Hill için anahtar matrisi zorunludur.')
            key_matrix = ast.literal_eval(key)
            decrypted = hill_decrypt(encrypted_message, key_matrix)

        elif algorithm == 'DES (Manual)':
            if not key:
                raise ValueError('DES (Manual) için 8 byte anahtar zorunludur.')
            decrypted = des_decrypt(encrypted_message, key)

        elif algorithm == 'DES (Library)':
            if SESSION_DES_KEY is None:
                raise ValueError('DES (Library) için önce RSA ile oturum anahtarı değişimi yapılmalı.')
            decrypted = des_lib_decrypt(encrypted_message, SESSION_DES_KEY)

        elif algorithm == 'AES (Manual)':
            if not key:
                raise ValueError('AES (Manual) için 16 byte anahtar zorunludur.')
            decrypted = aes_manual_decrypt(encrypted_message, key)

        elif algorithm == 'AES (Library)':
            if SESSION_AES_KEY is None:
                raise ValueError('AES (Library) için önce RSA ile oturum anahtarı değişimi yapılmalı.')
            decrypted = aes_lib_decrypt(encrypted_message, SESSION_AES_KEY)

        elif algorithm == 'RSA':
            decrypted = rsa_decrypt_text(RSA_PRIVATE_KEY, encrypted_message)

        else:
            raise ValueError('Geçersiz algoritma.')

        socketio.emit('message_decrypted', {'decrypted': decrypted})

    except Exception as e:
        socketio.emit('error', {'message': str(e)})


if __name__ == '__main__':
    socketio.run(app, debug=True)
