"""Password and token handling."""

import hashlib
import hmac
import os

from Crypto.Cipher import AES, ARC4, DES


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # vuln: weak_crypto


def hash_password_v2(password, salt):
    return hashlib.sha1(salt + password.encode()).hexdigest()  # vuln: weak_crypto


def hash_password_v3(password, salt):
    digest = hashlib.new("md5")  # vuln: weak_crypto
    digest.update(salt + password.encode())
    return digest.hexdigest()


def hash_password_good(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)  # safe: weak_crypto


def file_etag(data):
    return hashlib.md5(data, usedforsecurity=False).hexdigest()  # safe: weak_crypto


def sign(key, message):
    return hmac.new(key, message, hashlib.sha256).hexdigest()  # safe: weak_crypto


def encrypt_legacy(key, data):
    return DES.new(key, DES.MODE_ECB).encrypt(data)  # vuln: weak_crypto


def encrypt_stream(key, data):
    return ARC4.new(key).encrypt(data)  # vuln: weak_crypto


def encrypt_blocks(key, data):
    return AES.new(key, AES.MODE_ECB).encrypt(data)  # vuln: weak_crypto


def encrypt_good(key, data):
    """Authenticated: the caller stores nonce and tag and decrypts with decrypt_and_verify."""
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)  # safe: weak_crypto
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return nonce, ciphertext, tag
