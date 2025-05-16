import os
import secrets
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from flask import Flask, render_template

app = Flask(__name__)

backend = default_backend()
iterations = 100_000

SECRET_MESSAGE = b"CqE5_MD3JZ_nPTTz-zKPHgABhqCAAAAAAGgm56OnBxX-dW-ZaWvKQPqAuJebW_MwNNg7Z9PrdM5a_s0ln7iw9Tio1_ApUOFDLjdovFATgkOL2SQbliRvCv_YJGXgOb471DNGWNCUbnKbDxBBqA=="


def _derive_key(password: bytes, salt: bytes, iterations: int = iterations) -> bytes:
    """Derive a secret key from a given password and salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=backend,
    )
    return b64e(kdf.derive(password))


def password_encrypt(
    message: str, password: str, iterations: int = iterations
) -> bytes:
    salt = secrets.token_bytes(16)
    key = _derive_key(password.encode(), salt, iterations)
    return b64e(
        b"%b%b%b"
        % (
            salt,
            iterations.to_bytes(4, "big"),
            b64d(Fernet(key).encrypt(message.encode())),
        )
    )


def password_decrypt(token: bytes, password: str) -> str:
    decoded = b64d(token)
    salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
    iterations = int.from_bytes(iter, "big")
    key = _derive_key(password.encode(), salt, iterations)
    return Fernet(key).decrypt(token).decode()


@app.route("/")
def hello_world():
    password = os.getenv("SECRET_PASSWORD", "No Value!")
    try:
        decrypted_message = password_decrypt(SECRET_MESSAGE, password)
    except InvalidToken:
        decrypted_message = "Message could not be decrypted!"
    return render_template("./main.html", decrypted_value=decrypted_message)
