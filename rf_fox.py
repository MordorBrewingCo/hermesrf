import base64
import hashlib
import logging
import os
import threading
import time

import pyfldigi
from Crypto.Cipher import AES
from flask import Flask, request, render_template_string

# Constants
AES_KEY_SIZE = 16
AES_KEY = hashlib.sha256(b"d2a7a6abeb88d67684c8abb8fde01316").digest()[:AES_KEY_SIZE]

# Flask app setup
app = Flask(__name__)

# Initialize pyfldigi
fldigi_client = pyfldigi.Client()

# Logging setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Shared messages dictionary (with thread-safety)
messages_lock = threading.Lock()
messages = {"received": [], "transmitted": []}


# AES decryption function
def decrypt_message(encrypted_message, key):
    try:
        encrypted_data = base64.b64decode(encrypted_message)
        if len(encrypted_data) < AES.block_size:
            raise ValueError("Invalid encrypted data length.")
        iv = encrypted_data[:AES.block_size]
        ciphertext = encrypted_data[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CFB, iv)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext.decode('utf-8')
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        return None


# AES encryption function
def encrypt_message(key, message):
    iv = os.urandom(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    encrypted = iv + cipher.encrypt(message.encode())
    return base64.b64encode(encrypted).decode()


# Listener thread function
def fldigi_listener():
    logger.info("Starting fldigi listener thread...")
    while True:
        try:
            received_text = fldigi_client.text.get_rx_data()
            if received_text:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

                with messages_lock:
                    decrypted_text = decrypt_message(received_text, AES_KEY)
                    messages["received"].append({
                        "message": received_text,
                        "decrypted": decrypted_text,
                        "timestamp": timestamp,
                    })
                if decrypted_text:
                    logger.info(f"Decrypted message: {decrypted_text}")
                else:
                    logger.info(f"Received plaintext message: {received_text}")

            time.sleep(0.5)  # Improved responsiveness
        except Exception as e:
            logger.error(f"Error in fldigi listener: {e}")
            time.sleep(5)


@app.route("/", methods=["GET", "POST"])
def index():
    try:
        current_mode = fldigi_client.modem.name
        modes = fldigi_client.modem.names

        if request.method == "POST":
            new_mode = request.form.get("mode")
            if new_mode and new_mode in modes:
                fldigi_client.modem.name = new_mode
                logger.info(f"Mode changed to {new_mode}")

        return render_template_string(
            '''
            <!doctype html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>RF Fox</title>
            </head>
            <body>
                <h1>Broadcast a Message</h1>
                <form method="POST" action="/broadcast">
                    <label for="message">Message:</label>
                    <textarea id="message" name="message" required style="resize: both; width: 100%; height: 100px;"></textarea>
                    <br><br>
                    <label for="encryption">Send as:</label>
                    <select id="encryption" name="encryption">
                        <option value="encrypted" selected>Encrypted</option>
                        <option value="unencrypted">Unencrypted</option>
                    </select>
                    <br><br>
                    <input type="submit" value="Broadcast">
                </form>
                <h2>Operating Mode</h2>
                <form method="POST" action="/">
                    <label for="mode">Select Mode:</label>
                    <select id="mode" name="mode">
                        {% for mode in modes %}
                        <option value="{{ mode }}" {% if mode == current_mode %}selected{% endif %}>{{ mode }}</option>
                        {% endfor %}
                    </select>
                    <button type="submit">Change Mode</button>
                </form>
                <h2>Current Mode: {{ current_mode }}</h2>
                <h2>Received Messages</h2>
                <ul>
                {% for msg in messages["received"] %}
                    <li>{{ msg.timestamp }} - {{ msg.message }}</li>
                {% endfor %}
                </ul>
                <h2>Transmitted Messages</h2>
                <ul>
                {% for msg in messages["transmitted"] %}
                    <li>
                        <strong>Timestamp:</strong> {{ msg.timestamp }}<br>
                        {% if msg.encrypted %}
                            <strong>Encrypted:</strong> {{ msg.encrypted }}<br>
                            <strong>Decrypted:</strong> {{ msg.decrypted }}
                        {% else %}
                            <strong>Message:</strong> {{ msg.decrypted }}
                        {% endif %}
                    </li>
                {% endfor %}
                </ul>
            </body>
            </html>
            ''',
            messages=messages,
            modes=modes,
            current_mode=current_mode,
        )
    except Exception as e:
        logger.error(f"Error in index route: {e}")
        return "<h1>Error loading index page</h1>"


@app.route("/broadcast", methods=["POST"])
def broadcast():
    try:
        message = request.form.get("message")
        encryption_choice = request.form.get("encryption")

        if not message or len(message) > 1024:
            return "<h1>Error: Message cannot be empty or too long!</h1><a href='/'>Try Again</a>"

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        if encryption_choice == "unencrypted":
            fldigi_client.text.clear_tx()
            fldigi_client.text.add_tx(message)
            fldigi_client.main.tx()
        else:
            encrypted_message = encrypt_message(AES_KEY, message)
            fldigi_client.text.clear_tx()
            fldigi_client.text.add_tx(encrypted_message)
            fldigi_client.main.tx()

        with messages_lock:
            messages["transmitted"].append({
                "encrypted": encrypt_message(AES_KEY, message) if encryption_choice == "encrypted" else None,
                "decrypted": message,
                "timestamp": timestamp,
            })

        return "<h1>Message Broadcast Successfully!</h1><a href='/'>Back</a>"
    except Exception as e:
        logger.error(f"Error during broadcast: {e}")
        return f"<h1>Error: {str(e)}</h1><a href='/'>Try Again</a>"


if __name__ == "__main__":
    listener_thread = threading.Thread(target=fldigi_listener, daemon=True)
    listener_thread.start()
    app.run(host="0.0.0.0", port=5000, debug=True)
