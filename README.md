RF Fox: Secure Message Broadcasting with Fldigi

RF Fox is a Flask-based application that enables secure message broadcasting using the Fldigi software modem. Messages can be encrypted using AES encryption or sent unencrypted, depending on user preference. It also includes a web interface for managing messages and operating modes.
Features

    Secure Broadcasting: Messages can be sent encrypted with AES-128 encryption.
    Unencrypted Option: Allows sending plain-text messages when encryption is not required.
    Web Interface: Includes an intuitive web UI for:
        Sending messages
        Viewing transmitted and received messages
        Switching between operating modes supported by Fldigi
    Real-Time Communication: Uses the Fldigi XML-RPC interface for communication with the modem.

Requirements

    Python 3.6+
    Fldigi (configured with XML-RPC enabled)
    Required Python Libraries:
        pyfldigi
        flask
        pycryptodome

Installation
1. Install Fldigi

Ensure that Fldigi is installed on your system and XML-RPC is enabled. To enable XML-RPC in Fldigi:

    Open Fldigi.
    Navigate to Configure > Misc > Services.
    Enable the XML-RPC server and set the port (default is 7362).

2. Clone the Repository

Clone this repository to your local machine:

git clone https://github.com/your-username/rf-fox.git
cd rf-fox

3. Install Python Dependencies

Install the required Python libraries using pip:

pip install flask pyfldigi pycryptodome

Usage
1. Start the Application

Run the Python script:

python app.py

2. Access the Web Interface

Open your browser and go to:

http://localhost:5000

3. Broadcast a Message

    Enter your message in the "Broadcast a Message" section.
    Select whether to send the message as "Encrypted" or "Unencrypted."
    Click "Broadcast" to send the message.

4. Change Operating Mode

    Use the dropdown menu in the "Operating Mode" section to select a supported Fldigi mode.
    Click "Change Mode" to apply the change.

Web Interface Overview
Sections

    Broadcast a Message:
        Input your message.
        Choose encryption type (encrypted or unencrypted).
        Click "Broadcast" to send.

    Operating Mode:
        Select the Fldigi mode from the dropdown.
        Apply the mode change using the "Change Mode" button.

    Received Messages:
        Displays all messages received via Fldigi, with timestamps.

    Transmitted Messages:
        Shows both encrypted and unencrypted messages sent, along with timestamps.

Code Overview
Key Components

    AES Encryption and Decryption:
        Encryption is performed using AES in CFB mode (encrypt_message).
        Decryption ensures data integrity (decrypt_message).

    Fldigi Listener:
        A background thread listens for incoming messages from Fldigi using the XML-RPC interface (fldigi_listener).

    Flask Web Server:
        Provides a user-friendly interface to interact with the Fldigi modem.

File Structure

.
├── app.py         # Main application script
├── requirements.txt # Python dependencies (optional)
└── README.md      # Project documentation

Examples
Sending an Encrypted Message

    Enter the message:

    Hello, this is a secure message!

    Select "Encrypted" from the dropdown.
    Click "Broadcast."
    View the message in the "Transmitted Messages" section:
        Encrypted text: bGF4eERBT0NlZGUy...
        Decrypted text: Hello, this is a secure message!

Troubleshooting
Common Issues

    Fldigi Not Running: Ensure that Fldigi is installed and running with XML-RPC enabled.

    Connection Error: Verify that the XML-RPC server is reachable at http://localhost:7362.

    Missing Dependencies: Install required Python libraries using pip install -r requirements.txt.

License

This project is licensed under the MIT License. See the LICENSE file for details.
Contributing

Contributions are welcome! Please submit a pull request or open an issue to suggest improvements or report bugs.
