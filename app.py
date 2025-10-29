from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from crypto_algorithms import *

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

received_message = ""

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/client')
def client_page():
    return render_template('client.html')

@app.route('/server')
def server_page():
    return render_template('server.html', message=received_message)

# ---------------- SocketIO Events ----------------
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
        try:
            rails = int(key) if key and key.isdigit() and int(key) >= 2 else 3
        except:
            rails = 3
        encrypted = rail_fence_encrypt(message, rails)
    elif algo == "Route Cipher":
        try:
            width = int(key) if key and key.isdigit() and int(key) >= 2 else 5
        except:
            width = 5
        encrypted = route_encrypt(message, width=width)
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
        try:
            rails = int(key) if key and key.isdigit() and int(key) >= 2 else 3
        except:
            rails = 3
        decrypted = rail_fence_decrypt(received_message, rails)
    elif algo == "Route Cipher":
        try:
            width = int(key) if key and key.isdigit() and int(key) >= 2 else 5
        except:
            width = 5
        decrypted = route_decrypt(received_message, width=width)
    else:
        decrypted = received_message

    emit('receive_decrypted', {'decrypted': decrypted}, broadcast=True)

if __name__ == '__main__':
    socketio.run(app, debug=True)
