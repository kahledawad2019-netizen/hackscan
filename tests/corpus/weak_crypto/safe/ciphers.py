import os

from mylib.constants import MODE_ECB as LIB_ECB

from Crypto.Cipher import AES, ChaCha20_Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def aes_gcm(key, data):
    nonce = os.urandom(12)
    return AES.new(key, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(data)


def chacha(key):
    return ChaCha20_Poly1305.new(key=key)


def cryptography_gcm(key, iv):
    return Cipher(algorithms.AES(key), modes.GCM(iv))


def aead(key):
    return AESGCM(key)


class LocalCipher:
    def new(self, key, mode):
        return (key, mode)


def unrelated_new(key):
    # a .new() that is not a cipher constructor, even with an ECB-looking constant
    return LocalCipher().new(key, "MODE_ECB")


def des_named_variable(DES):
    # a parameter named DES is not the Crypto.Cipher module
    return DES.new("key")


def cipher_module_lookup(key):
    # a call on the cipher module that is not new(): MODE_ECB is only a value here
    return AES.__dict__.get(key, AES.MODE_ECB)


def local_name_is_not_the_constant(key):
    # a local variable named MODE_ECB holds GCM here; variable modes are out of scope
    MODE_ECB = AES.MODE_GCM
    return AES.new(key, MODE_ECB)


def ecb_name_from_another_library(key):
    # MODE_ECB from a module that is not a cipher package is not the cipher constant
    return AES.new(key, LIB_ECB)
