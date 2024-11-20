import base64
import hashlib
import logging
import os
import time

import pyfldigi  # Correctly using the pyfldigi library
from Crypto.Cipher import AES
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask, request

# Constants
AES_KEY_SIZE = 16

# Define the AES encryption key
# A generated AES 128 bit key is provided, but change this for field use
AES_KEY = hashlib.sha256(b"d2a7a6abeb88d67684c8abb8fde01316").digest()[:AES_KEY_SIZE]

# Flask app setup
app = Flask(__name__)

# Initialize pyfldigi
fldigi_client = pyfldigi.Client()

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# AES decryption function
def decrypt_message(encrypted_message, key):
    try:
        # Decode the base64 encoded message
        encrypted_data = base64.b64decode(encrypted_message)
        # Extract the IV and ciphertext
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        # Initialize the cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        # Decrypt the ciphertext
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        # Unpad the plaintext
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext.decode('utf-8')
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        return None


# Listener thread function
def fldigi_listener(fldigi_client, aes_key):
    logger.info("Starting fldigi listener thread...")
    while True:
        try:
            # Retrieve received text from fldigi
            received_text = fldigi_client.text.get_rx()
            if received_text:
                logger.info(f"Received message: {received_text}")
                # Attempt to decrypt the message
                decrypted_message = decrypt_message(received_text, aes_key)
                if decrypted_message:
                    logger.info(f"Decrypted message: {decrypted_message}")
                else:
                    logger.warning("Failed to decrypt the received message.")
            time.sleep(1)  # Adjust the sleep interval as needed
        except Exception as e:
            logger.error(f"Error in fldigi listener: {e}")
            time.sleep(5)  # Wait before retrying in case of an error


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
        encrypted_message = encrypt_message(AES_KEY, message)

        # Send the encrypted message via FLDigi
        fldigi_client.text.clear_tx()  # Clear previous transmit text
        fldigi_client.text.add_tx(encrypted_message)  # Queue the encrypted message for transmission
        fldigi_client.main.tx()  # Start transmitting
        print(f"Message sent via FLDigi: {encrypted_message}")

        return f'''
        <h1>Message Broadcast Successfully!</h1>
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
