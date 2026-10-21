"""Weak ciphers: broken or legacy algorithms, and ECB mode.

Reported calls:
- a broken or legacy algorithm constructed through PyCryptodome / PyCrypto (`Crypto.Cipher` or
  `Cryptodome.Cipher`: DES, DES3, ARC2, ARC4, Blowfish, CAST, XOR), `cryptography`
  (`algorithms.TripleDES`, `Blowfish`, `ARC4`, `CAST5`, `IDEA`, `SEED`, also from
  `cryptography.hazmat.decrepit`) or pyDes;
- ECB mode: a PyCryptodome / PyCrypto `new(key, MODE_ECB)` (positional or `mode=`), or
  `cryptography`'s `modes.ECB()`.

A call that is both (DES in ECB mode) is reported once, for the algorithm. Not reported:
unauthenticated modes such as CBC or CTR without a MAC (whether a MAC is applied elsewhere is not
visible at the call), a mode given as a number or through a variable, and PyCrypto's default
mode when none is given. These findings get no automatic fix: replacing a cipher changes the
format of stored or exchanged data.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable

from hackscan.core.models import Severity
from hackscan.plugins.base import FileContext, Match, RulePlugin, keyword

PYCRYPTO_PACKAGES = ("Crypto.Cipher", "Cryptodome.Cipher")
PYCRYPTO_BROKEN = ("DES", "DES3", "ARC2", "ARC4", "Blowfish", "CAST", "XOR")
CRYPTOGRAPHY_PACKAGES = (
    "cryptography.hazmat.primitives.ciphers.algorithms",
    "cryptography.hazmat.decrepit.ciphers.algorithms",
)
CRYPTOGRAPHY_BROKEN = ("TripleDES", "Blowfish", "ARC4", "CAST5", "IDEA", "SEED")

# Fully-qualified constructor -> the algorithm's display name.
BROKEN_CONSTRUCTORS: dict[str, str] = {
    **{f"{pkg}.{alg}.new": alg for pkg in PYCRYPTO_PACKAGES for alg in PYCRYPTO_BROKEN},
    **{f"{pkg}.{alg}": alg for pkg in CRYPTOGRAPHY_PACKAGES for alg in CRYPTOGRAPHY_BROKEN},
    "pyDes.des": "DES",
    "pyDes.triple_des": "3DES",
}
CRYPTOGRAPHY_ECB = "cryptography.hazmat.primitives.ciphers.modes.ECB"
PYCRYPTO_NEW_PREFIXES = tuple(f"{pkg}." for pkg in PYCRYPTO_PACKAGES)
MODE_POSITION = 1  # Crypto.Cipher.<X>.new(key, mode, ...)

BROKEN_ADVICE = (
    "use AES-GCM or ChaCha20-Poly1305 (authenticated encryption) and plan a migration of data "
    "already encrypted with it."
)
ECB_ADVICE = (
    "ECB encrypts equal blocks to equal ciphertext and reveals patterns; use an authenticated "
    "mode such as GCM (or ChaCha20-Poly1305) with a unique nonce per message."
)


class WeakCipher(RulePlugin):
    rule_id = "HS-CRYPTO-002"
    name = "weak-cipher"
    description = "A broken or legacy cipher, or ECB mode, is used."
    severity = Severity.MEDIUM
    cwe = ("CWE-327",)
    default_confidence = 80

    def check(self, node: ast.AST, ctx: FileContext) -> Iterable[Match]:
        assert isinstance(node, ast.Call)
        if message := weak_cipher_call(node, ctx):
            yield Match(node, message)


def weak_cipher_call(call: ast.Call, ctx: FileContext) -> str | None:
    """The finding message when `call` constructs a broken or legacy cipher or uses ECB mode, else
    None. Any possible resolution counts (conditional imports): the cautious reading."""
    names = ctx.call_names(call)
    if broken := sorted(BROKEN_CONSTRUCTORS[n] for n in names & BROKEN_CONSTRUCTORS.keys()):
        return f"Broken or legacy cipher {broken[0]} is used: {BROKEN_ADVICE}"
    if CRYPTOGRAPHY_ECB in names or (_is_pycrypto_new(names) and _mode_is_ecb(call, ctx)):
        return f"Block cipher in ECB mode: {ECB_ADVICE}"
    return None


def _is_pycrypto_new(names: frozenset[str]) -> bool:
    return any(n.startswith(PYCRYPTO_NEW_PREFIXES) and n.endswith(".new") for n in names)


def _mode_is_ecb(call: ast.Call, ctx: FileContext) -> bool:
    """The mode argument resolves, through the file's imports, to a PyCryptodome / PyCrypto
    MODE_ECB constant (`AES.MODE_ECB`, `MODE_ECB` or an alias imported from a cipher module). A
    local variable resolves to nothing and is not reported (variable modes are out of scope).
    With unpacked arguments before it, the value in the mode position still counts."""
    mode = keyword(call, "mode")
    if mode is None:
        if len(call.args) <= MODE_POSITION:
            return False
        mode = call.args[MODE_POSITION]
    return any(
        n.startswith(PYCRYPTO_NEW_PREFIXES) and n.endswith(".MODE_ECB")
        for n in ctx.resolve_all(mode)
    )
