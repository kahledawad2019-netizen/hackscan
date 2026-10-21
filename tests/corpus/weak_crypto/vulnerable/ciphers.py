import pyDes
from Crypto.Cipher import AES, ARC4, DES, DES3, Blowfish
from Crypto.Cipher.AES import MODE_ECB
from Crypto.Cipher.AES import MODE_ECB as ECB
from Cryptodome.Cipher import AES as DomeAES
from Cryptodome.Cipher import ARC2 as RC2
from cryptography.hazmat.decrepit.ciphers import algorithms as decrepit
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def legacy_des(key, data):
    return DES.new(key, DES.MODE_ECB).encrypt(data)  # expect: HS-CRYPTO-002


def stream_rc4(key, data):
    return ARC4.new(key).encrypt(data)  # expect: HS-CRYPTO-002


def triple_des(key, iv):
    return DES3.new(key, DES3.MODE_CBC, iv)  # expect: HS-CRYPTO-002


def blowfish(key, iv):
    return Blowfish.new(key, Blowfish.MODE_CBC, iv)  # expect: HS-CRYPTO-002


def rc2_alias(key, iv):
    return RC2.new(key, RC2.MODE_CBC, iv)  # expect: HS-CRYPTO-002


def aes_ecb(key, data):
    return AES.new(key, AES.MODE_ECB).encrypt(data)  # expect: HS-CRYPTO-002


def aes_ecb_keyword(key):
    return DomeAES.new(key, mode=DomeAES.MODE_ECB)  # expect: HS-CRYPTO-002


def aes_ecb_imported_name(key):
    return AES.new(key, MODE_ECB)  # expect: HS-CRYPTO-002


def cryptography_triple_des(key):
    algorithm = algorithms.TripleDES(key)  # expect: HS-CRYPTO-002
    return Cipher(algorithm, modes.CBC(b"0" * 8))


def cryptography_ecb(key):
    return Cipher(algorithms.AES(key), modes.ECB())  # expect: HS-CRYPTO-002


def cryptography_decrepit(key):
    return decrepit.CAST5(key)  # expect: HS-CRYPTO-002


def pydes(key):
    return pyDes.des(key)  # expect: HS-CRYPTO-002


def aes_ecb_alias(key):
    return AES.new(key, mode=ECB)  # expect: HS-CRYPTO-002
