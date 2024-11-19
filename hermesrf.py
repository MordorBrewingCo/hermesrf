import hashlib
import os

import pyfldigi  # Correctly using the pyfldigi library
from Crypto.Cipher import AES
from flask import Flask, request

# Constants
AES_KEY_SIZE = 16

# Flask app setup
app = Flask(__name__)

# Initialize pyfldigi
fldigi_client = pyfldigi.Client()


# Encryption helper function
def encrypt_message(key, message):
    iv = os.urandom(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    encrypted = iv + cipher.encrypt(message.encode())
    return encrypted.hex()


@app.route("/", methods=["GET"])
def index():
    """Web interface to enter and broadcast messages."""
    return '''
    <!doctype html>
    <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>AirChat Broadcaster</title>
        </head>
        <body>
            <h1>Broadcast a Message</h1>
            <form method="POST" action="/broadcast">
                <label for="message">Message:</label>
                <input type="text" id="message" name="message" required>
                <br><br>
                <input type="submit" value="Broadcast">
            </form>
        </body>
    </html>
    '''


@app.route("/broadcast", methods=["POST"])
def broadcast():
    """Broadcast the message using FLDigi."""
    try:
        # Get the message from the form
        message = request.form.get("message")
        if not message:
            return '''
            <h1>Error: Message cannot be empty!</h1>
            <a href="/">Try Again</a>
            '''

        # Encrypt the message
        key = hashlib.sha256(b"your_secret_key").digest()[:AES_KEY_SIZE]
        encrypted_message = encrypt_message(key, message)

        # Send the encrypted message via FLDigi
        fldigi_client.text.clear_tx()  # Clear previous transmit text
        fldigi_client.text.add_tx(encrypted_message)  # Queue the encrypted message for transmission
        fldigi_client.main.tx()  # Start transmitting
        print(f"Message sent via FLDigi: {encrypted_message}")

        return f'''
        <h1>Message Broadcasted Successfully!</h1>
        <p>Your message: {message}</p>
        <p>Encrypted message: {encrypted_message}</p>
        <a href="/">Send Another Message</a>
        '''
    except Exception as e:
        return f'''
        <h1>Error: {str(e)}</h1>
        <a href="/">Try Again</a>
        '''


if __name__ == "__main__":
    # Run Flask app
    app.run(host="0.0.0.0", port=5000, debug=True)
