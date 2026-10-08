import hashlib
from hashlib import sha1


def password_hash(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()  # expect: VH-CRYPTO-001


def token(data: bytes) -> str:
    return sha1(data).hexdigest()  # expect: VH-CRYPTO-001


def by_name(data: bytes) -> str:
    return hashlib.new("MD5", data).hexdigest()  # expect: VH-CRYPTO-001


def explicit_security(data: bytes) -> str:
    return hashlib.sha1(data, usedforsecurity=True).hexdigest()  # expect: VH-CRYPTO-001


def algorithm_variable(data: bytes) -> str:
    algorithm = "sha1"
    return hashlib.new(algorithm, data).hexdigest()  # expect: VH-CRYPTO-001
