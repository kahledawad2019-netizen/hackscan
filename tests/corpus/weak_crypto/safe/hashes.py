import hashlib


def strong(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checksum(data: bytes) -> str:
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def by_name_strong(data: bytes) -> str:
    return hashlib.new("sha3_256", data).hexdigest()


def blake(data: bytes) -> str:
    return hashlib.blake2b(data).hexdigest()
