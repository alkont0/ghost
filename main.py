from flask import Flask, request, jsonify
from flask_cors import CORS
from jsonschema import validate, ValidationError
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import urlsafe_b64encode, urlsafe_b64decode
from os import urandom

app = Flask(__name__)
CORS(app, origins=["http://127.0.0.1:5000/encrypt"])

# JSON Schema للتحقق من بنية البيانات
schema = {
    "type": "object",
    "properties": {
        "text": {"type": "string"}
    },
    "required": ["text"]
}

def encrypt_text(text, key):
    backend = default_backend()
    iv = urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=backend)
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return urlsafe_b64encode(iv + ciphertext).decode()

@app.route('/encrypt', methods=['POST'])
def encrypt_api():
    try:
        # التحقق من تنسيق البيانات
        validate(instance=request.json, schema=schema)
    except ValidationError as e:
        return jsonify({"error": "Invalid input data"}), 400

    text_to_encrypt = request.json['text']
    key = urandom(32)
    encrypted_text = encrypt_text(text_to_encrypt, key)
    formatted_key = ", ".join(map(str, key))
    response = {'encrypted_text': encrypted_text, 'key': formatted_key}
    return jsonify(response)
