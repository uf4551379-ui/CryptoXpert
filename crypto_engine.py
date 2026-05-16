"""
Educational cryptography engine for an Information Security project.
Algorithms included:
- Caesar Cipher
- Affine Cipher
- Vigenere Cipher
- Monoalphabetic Substitution Cipher
- RSA demo with full modular arithmetic steps
- DSA demo for digital signature sign/verify
- ASA/AES option using local PyCryptodome AES-CBC, with mathematical explanation

This project is for learning and lab demonstration, not production security.
"""

from __future__ import annotations

import base64
import hashlib
import math
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


@dataclass
class CryptoResponse:
    result: str
    steps: List[str]
    table: List[Dict[str, Any]]
    warnings: List[str]
    meta: Dict[str, Any]


class CryptoError(ValueError):
    pass


# ----------------------------- Common helpers -----------------------------

def clean_key(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value).strip()


def parse_int(value: Any, name: str, default: int | None = None) -> int:
    if value is None or str(value).strip() == "":
        if default is None:
            raise CryptoError(f"{name} is required.")
        return default
    try:
        return int(str(value).strip())
    except ValueError as exc:
        raise CryptoError(f"{name} must be a valid integer.") from exc


def mod_inverse(a: int, m: int) -> int:
    """Return x where (a*x) % m == 1."""
    a = a % m
    if math.gcd(a, m) != 1:
        raise CryptoError(f"Modular inverse does not exist because gcd({a}, {m}) != 1.")

    old_r, r = a, m
    old_s, s = 1, 0
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    return old_s % m


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    limit = int(n ** 0.5) + 1
    for i in range(3, limit, 2):
        if n % i == 0:
            return False
    return True


def shift_letter(ch: str, shift: int) -> Tuple[str, int, int]:
    base = ord('A') if ch.isupper() else ord('a')
    x = ord(ch) - base
    y = (x + shift) % 26
    return chr(base + y), x, y


def letter_value(ch: str) -> int:
    return ord(ch.upper()) - ord('A')


def preserve_case(original: str, upper_letter: str) -> str:
    return upper_letter if original.isupper() else upper_letter.lower()


# ----------------------------- Caesar Cipher ------------------------------

def caesar_cipher(text: str, action: str, keys: Dict[str, Any]) -> CryptoResponse:
    shift = parse_int(keys.get("shift"), "Shift", 3) % 26
    effective_shift = shift if action == "encrypt" else -shift
    result_chars: List[str] = []
    table: List[Dict[str, Any]] = []

    steps = [
        "Caesar Cipher uses a fixed shift value.",
        f"Formula for encryption: C = (P + k) mod 26",
        f"Formula for decryption: P = (C - k) mod 26",
        f"Selected shift k = {shift}. Effective shift used now = {effective_shift}.",
    ]

    for ch in text:
        if ch.isalpha():
            out, before, after = shift_letter(ch, effective_shift)
            result_chars.append(out)
            table.append({
                "char": ch,
                "value_before": before,
                "formula": f"({before} {'+' if effective_shift >= 0 else '-'} {abs(effective_shift)}) mod 26",
                "value_after": after,
                "output": out,
            })
        else:
            result_chars.append(ch)
            table.append({"char": ch, "value_before": "-", "formula": "unchanged", "value_after": "-", "output": ch})

    result = "".join(result_chars)
    return CryptoResponse(result, steps, table, [], {"cipher": "Caesar", "shift": shift})


# ----------------------------- Affine Cipher ------------------------------

def affine_cipher(text: str, action: str, keys: Dict[str, Any]) -> CryptoResponse:
    a = parse_int(keys.get("a"), "a", 5)
    b = parse_int(keys.get("b"), "b", 8)
    if math.gcd(a, 26) != 1:
        raise CryptoError("For Affine Cipher, a must be coprime with 26. Valid examples: 1,3,5,7,9,11,15,17,19,21,23,25.")

    a_inv = mod_inverse(a, 26)
    result_chars: List[str] = []
    table: List[Dict[str, Any]] = []
    steps = [
        "Affine Cipher combines multiplication and addition.",
        "Encryption formula: C = (aP + b) mod 26",
        "Decryption formula: P = a⁻¹(C - b) mod 26",
        f"Given a = {a}, b = {b}. Since gcd({a}, 26) = 1, decryption is possible.",
        f"Modular inverse: a⁻¹ = {a_inv}, because ({a} × {a_inv}) mod 26 = 1.",
    ]

    for ch in text:
        if ch.isalpha():
            x = letter_value(ch)
            if action == "encrypt":
                y = (a * x + b) % 26
                formula = f"({a}×{x} + {b}) mod 26"
            else:
                y = (a_inv * (x - b)) % 26
                formula = f"{a_inv}×({x} - {b}) mod 26"
            out = preserve_case(ch, ALPHABET[y])
            result_chars.append(out)
            table.append({"char": ch, "value_before": x, "formula": formula, "value_after": y, "output": out})
        else:
            result_chars.append(ch)
            table.append({"char": ch, "value_before": "-", "formula": "unchanged", "value_after": "-", "output": ch})

    return CryptoResponse("".join(result_chars), steps, table, [], {"cipher": "Affine", "a": a, "b": b, "a_inverse": a_inv})


# ---------------------------- Vigenere Cipher -----------------------------

def vigenere_cipher(text: str, action: str, keys: Dict[str, Any]) -> CryptoResponse:
    key = re.sub(r"[^A-Za-z]", "", clean_key(keys.get("key"), "KEY"))
    if not key:
        raise CryptoError("Vigenere key must contain at least one alphabet letter.")

    key_values = [letter_value(ch) for ch in key]
    key_index = 0
    result_chars: List[str] = []
    table: List[Dict[str, Any]] = []
    steps = [
        "Vigenere Cipher uses a repeating keyword.",
        "Encryption formula: C = (P + K) mod 26",
        "Decryption formula: P = (C - K) mod 26",
        f"Keyword = {key.upper()}, key numeric values = {key_values}.",
    ]

    for ch in text:
        if ch.isalpha():
            x = letter_value(ch)
            k = key_values[key_index % len(key_values)]
            if action == "encrypt":
                y = (x + k) % 26
                formula = f"({x} + {k}) mod 26"
            else:
                y = (x - k) % 26
                formula = f"({x} - {k}) mod 26"
            out = preserve_case(ch, ALPHABET[y])
            result_chars.append(out)
            table.append({
                "char": ch,
                "key_char": key[key_index % len(key)].upper(),
                "value_before": x,
                "formula": formula,
                "value_after": y,
                "output": out,
            })
            key_index += 1
        else:
            result_chars.append(ch)
            table.append({"char": ch, "key_char": "-", "value_before": "-", "formula": "unchanged", "value_after": "-", "output": ch})

    return CryptoResponse("".join(result_chars), steps, table, [], {"cipher": "Vigenere", "key": key.upper()})


# ------------------------- Substitution Cipher ----------------------------

def substitution_cipher(text: str, action: str, keys: Dict[str, Any]) -> CryptoResponse:
    raw_key = clean_key(keys.get("substitution_key"), "QWERTYUIOPASDFGHJKLZXCVBNM").upper()
    key = re.sub(r"[^A-Z]", "", raw_key)
    if len(key) != 26 or len(set(key)) != 26:
        raise CryptoError("Substitution key must contain all 26 unique alphabet letters. Example: QWERTYUIOPASDFGHJKLZXCVBNM")

    enc_map = {ALPHABET[i]: key[i] for i in range(26)}
    dec_map = {key[i]: ALPHABET[i] for i in range(26)}
    active_map = enc_map if action == "encrypt" else dec_map

    result_chars: List[str] = []
    table: List[Dict[str, Any]] = []
    steps = [
        "Monoalphabetic Substitution Cipher replaces every alphabet letter with a fixed mapped letter.",
        f"Plain alphabet:  {ALPHABET}",
        f"Cipher alphabet: {key}",
        "For encryption, use Plain → Cipher mapping. For decryption, use Cipher → Plain mapping.",
    ]

    for ch in text:
        if ch.isalpha():
            up = ch.upper()
            mapped = active_map[up]
            out = preserve_case(ch, mapped)
            result_chars.append(out)
            table.append({"char": ch, "value_before": up, "formula": f"map({up}) = {mapped}", "value_after": mapped, "output": out})
        else:
            result_chars.append(ch)
            table.append({"char": ch, "value_before": "-", "formula": "unchanged", "value_after": "-", "output": ch})

    return CryptoResponse("".join(result_chars), steps, table, [], {"cipher": "Substitution", "key": key})


# ---------------------------------- RSA -----------------------------------

def rsa_cipher(text: str, action: str, keys: Dict[str, Any]) -> CryptoResponse:
    p = parse_int(keys.get("p"), "p", 61)
    q = parse_int(keys.get("q"), "q", 53)
    e = parse_int(keys.get("e"), "e", 17)

    if not is_prime(p) or not is_prime(q):
        raise CryptoError("RSA requires prime numbers p and q. Example p=61, q=53.")
    if p == q:
        raise CryptoError("RSA requires p and q to be different prime numbers.")

    n = p * q
    phi = (p - 1) * (q - 1)
    if math.gcd(e, phi) != 1:
        raise CryptoError(f"e must be coprime with φ(n). Current gcd({e}, {phi}) != 1.")
    d = mod_inverse(e, phi)

    steps = [
        "RSA is an asymmetric algorithm: public key encrypts, private key decrypts.",
        f"Choose primes p = {p}, q = {q}.",
        f"Calculate n = p × q = {p} × {q} = {n}.",
        f"Calculate φ(n) = (p-1)(q-1) = {p-1} × {q-1} = {phi}.",
        f"Public exponent e = {e}; gcd({e}, {phi}) = 1, so it is valid.",
        f"Private exponent d = e⁻¹ mod φ(n) = {d}, because ({e} × {d}) mod {phi} = 1.",
    ]

    table: List[Dict[str, Any]] = []
    warnings: List[str] = [
        "This RSA uses small numbers for classroom demonstration. Real RSA uses very large primes."
    ]

    if action == "encrypt":
        if not text:
            raise CryptoError("Text is required for RSA encryption.")
        encrypted_numbers: List[str] = []
        max_char = max(ord(ch) for ch in text)
        if n <= max_char:
            raise CryptoError(f"n = {n} is too small for this text. Use larger p and q so n is greater than every character ASCII value.")
        for ch in text:
            m = ord(ch)
            c = pow(m, e, n)
            encrypted_numbers.append(str(c))
            table.append({
                "char": ch,
                "value_before": m,
                "formula": f"{m}^{e} mod {n}",
                "value_after": c,
                "output": c,
            })
        result = " ".join(encrypted_numbers)
    else:
        numbers = [x for x in re.split(r"[\s,]+", text.strip()) if x]
        if not numbers:
            raise CryptoError("For RSA decryption, enter encrypted numbers separated by spaces or commas.")
        decrypted_chars: List[str] = []
        for item in numbers:
            try:
                c = int(item)
            except ValueError as exc:
                raise CryptoError("RSA encrypted text must contain numbers only for decryption.") from exc
            m = pow(c, d, n)
            if not (0 <= m <= 1114111):
                raise CryptoError("Decryption produced an invalid Unicode value. Check p, q, e, and ciphertext.")
            ch = chr(m)
            decrypted_chars.append(ch)
            table.append({
                "char": c,
                "value_before": c,
                "formula": f"{c}^{d} mod {n}",
                "value_after": m,
                "output": ch,
            })
        result = "".join(decrypted_chars)

    return CryptoResponse(result, steps, table, warnings, {"cipher": "RSA", "p": p, "q": q, "n": n, "phi": phi, "e": e, "d": d})


# ---------------------------------- DSA -----------------------------------

def dsa_process(text: str, action: str, keys: Dict[str, Any]) -> CryptoResponse:
    # Small educational DSA parameters. q divides p-1: 29 divides 58.
    p = parse_int(keys.get("dsa_p"), "p", 59)
    q = parse_int(keys.get("dsa_q"), "q", 29)
    g = parse_int(keys.get("dsa_g"), "g", 4)
    x = parse_int(keys.get("dsa_x"), "private key x", 5)
    k = parse_int(keys.get("dsa_k"), "random k", 7)

    if not is_prime(p) or not is_prime(q):
        raise CryptoError("DSA p and q must be prime numbers.")
    if (p - 1) % q != 0:
        raise CryptoError("DSA requires q to divide p-1.")
    if not (1 < g < p):
        raise CryptoError("DSA g must be between 1 and p.")
    if not (0 < x < q):
        raise CryptoError("DSA private key x must be in range 1 to q-1.")

    y = pow(g, x, p)
    h = sum(ord(ch) for ch in text) % q
    steps = [
        "DSA is not used for encryption. It is used for digital signatures.",
        f"Public parameters: p = {p}, q = {q}, g = {g}. Here q divides p-1 because {q} divides {p-1}.",
        f"Private key x = {x}.",
        f"Public key y = g^x mod p = {g}^{x} mod {p} = {y}.",
        f"Message hash for classroom demo: H(M) = sum(ASCII values) mod q = {h}.",
    ]
    table: List[Dict[str, Any]] = []
    warnings = [
        "This is an educational DSA demo with small numbers and a simple hash. Real DSA uses secure large parameters and SHA hashing."
    ]

    if action == "sign":
        if math.gcd(k, q) != 1 or not (0 < k < q):
            raise CryptoError("DSA k must be in range 1 to q-1 and gcd(k, q) must be 1.")
        r = pow(g, k, p) % q
        if r == 0:
            raise CryptoError("Generated r = 0. Choose a different k.")
        k_inv = mod_inverse(k, q)
        s = (k_inv * (h + x * r)) % q
        if s == 0:
            raise CryptoError("Generated s = 0. Choose a different k.")

        steps.extend([
            f"Choose temporary random k = {k}.",
            f"Calculate r = (g^k mod p) mod q = ({g}^{k} mod {p}) mod {q} = {r}.",
            f"Calculate k⁻¹ mod q = {k_inv}.",
            f"Calculate s = k⁻¹(H(M) + x×r) mod q = {k_inv}({h} + {x}×{r}) mod {q} = {s}.",
            f"Digital signature = (r, s) = ({r}, {s}).",
        ])
        table.append({"char": "H(M)", "value_before": h, "formula": "sum(ASCII) mod q", "value_after": h, "output": h})
        table.append({"char": "r", "value_before": k, "formula": f"({g}^{k} mod {p}) mod {q}", "value_after": r, "output": r})
        table.append({"char": "s", "value_before": k_inv, "formula": f"{k_inv}({h}+{x}×{r}) mod {q}", "value_after": s, "output": s})
        result = f"Signature: r={r}, s={s}\nPublic key y={y}"
        meta = {"cipher": "DSA", "p": p, "q": q, "g": g, "x": x, "y": y, "hash": h, "k": k, "r": r, "s": s}
    elif action == "verify":
        r = parse_int(keys.get("dsa_r"), "signature r")
        s = parse_int(keys.get("dsa_s"), "signature s")
        y_input = parse_int(keys.get("dsa_y"), "public key y", y)
        if not (0 < r < q and 0 < s < q):
            raise CryptoError("For DSA verification, r and s must be between 1 and q-1.")
        w = mod_inverse(s, q)
        u1 = (h * w) % q
        u2 = (r * w) % q
        v = ((pow(g, u1, p) * pow(y_input, u2, p)) % p) % q
        valid = v == r

        steps.extend([
            f"Given signature r = {r}, s = {s}, public key y = {y_input}.",
            f"Calculate w = s⁻¹ mod q = {s}⁻¹ mod {q} = {w}.",
            f"Calculate u1 = H(M)×w mod q = {h}×{w} mod {q} = {u1}.",
            f"Calculate u2 = r×w mod q = {r}×{w} mod {q} = {u2}.",
            f"Calculate v = ((g^u1 × y^u2) mod p) mod q = {v}.",
            f"Verification rule: valid if v == r. Here {v} {'==' if valid else '!='} {r}.",
        ])
        table.extend([
            {"char": "w", "value_before": s, "formula": f"{s}⁻¹ mod {q}", "value_after": w, "output": w},
            {"char": "u1", "value_before": h, "formula": f"{h}×{w} mod {q}", "value_after": u1, "output": u1},
            {"char": "u2", "value_before": r, "formula": f"{r}×{w} mod {q}", "value_after": u2, "output": u2},
            {"char": "v", "value_before": "-", "formula": f"(({g}^{u1} × {y_input}^{u2}) mod {p}) mod {q}", "value_after": v, "output": v},
        ])
        result = "Signature is VALID ✅" if valid else "Signature is NOT VALID ❌"
        meta = {"cipher": "DSA", "p": p, "q": q, "g": g, "y": y_input, "hash": h, "r": r, "s": s, "w": w, "u1": u1, "u2": u2, "v": v, "valid": valid}
    else:
        raise CryptoError("DSA supports only sign and verify actions.")

    return CryptoResponse(result, steps, table, warnings, meta)


# ------------------------------- AES / ASA --------------------------------

def _require_aes_library():
    try:
        from Crypto.Cipher import AES  # type: ignore
        from Crypto.Util.Padding import pad, unpad  # type: ignore
        return AES, pad, unpad
    except Exception as exc:  # pragma: no cover - depends on local environment
        raise CryptoError("AES/ASA requires PyCryptodome. Run: pip install -r requirements.txt") from exc


def asa_aes_cipher(text: str, action: str, keys: Dict[str, Any]) -> CryptoResponse:
    """AES-CBC implementation exposed as ASA/AES because students often write ASA by mistake."""
    AES, pad, unpad = _require_aes_library()
    password = clean_key(keys.get("aes_key"), "information-security-key")
    if not password:
        raise CryptoError("AES/ASA key is required.")

    key_hash = hashlib.sha256(password.encode("utf-8")).digest()
    aes_key = key_hash[:16]
    table: List[Dict[str, Any]] = []
    warnings = [
        "This option uses local AES-CBC from PyCryptodome. No online API is used.",
        "For learning, the app shows the block-level math concept. Production encryption also needs authentication such as HMAC/GCM.",
    ]
    steps = [
        "ASA option is implemented as AES-128 CBC for practical Information Security demonstration.",
        "AES is a symmetric block cipher. The same secret key is used for encryption and decryption.",
        "Key derivation: SHA-256(secret key), then first 16 bytes are used as AES-128 key.",
        f"SHA-256(key) starts with: {key_hash.hex()[:32]}...",
        "CBC idea: each plaintext block is XORed with the previous ciphertext block before AES encryption.",
    ]

    if action == "encrypt":
        iv = os.urandom(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        plain_bytes = text.encode("utf-8")
        padded = pad(plain_bytes, 16)
        encrypted = cipher.encrypt(padded)
        token = base64.b64encode(iv + encrypted).decode("utf-8")
        steps.extend([
            f"Plaintext bytes length = {len(plain_bytes)}.",
            f"After PKCS#7 padding, byte length = {len(padded)}. Block size = 16 bytes.",
            f"Random IV generated in hex = {iv.hex()}.",
            "Final output = Base64(IV + ciphertext), so IV is available for decryption.",
        ])
        for index in range(0, min(len(padded), 64), 16):
            block = padded[index:index+16]
            table.append({
                "char": f"Block {index//16 + 1}",
                "value_before": block.hex(),
                "formula": "CBC: AES_K(P_i XOR C_{i-1})",
                "value_after": encrypted[index:index+16].hex(),
                "output": encrypted[index:index+16].hex(),
            })
        result = token
        meta = {"cipher": "ASA/AES", "mode": "AES-128-CBC", "iv_hex": iv.hex(), "key_hash_preview": key_hash.hex()[:32]}
    elif action == "decrypt":
        try:
            raw = base64.b64decode(text)
        except Exception as exc:
            raise CryptoError("AES/ASA decryption input must be the Base64 output produced by encryption.") from exc
        if len(raw) < 32 or len(raw) % 16 != 0:
            raise CryptoError("Invalid AES/ASA ciphertext. It must contain IV + ciphertext blocks.")
        iv, encrypted = raw[:16], raw[16:]
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded = cipher.decrypt(encrypted)
        try:
            plain = unpad(padded, 16)
        except ValueError as exc:
            raise CryptoError("AES/ASA decryption failed. Check the secret key and ciphertext.") from exc
        result = plain.decode("utf-8", errors="replace")
        steps.extend([
            f"IV extracted from ciphertext: {iv.hex()}.",
            f"Ciphertext byte length = {len(encrypted)}.",
            "CBC decryption idea: P_i = AES_D(C_i) XOR C_{i-1}.",
            "PKCS#7 padding removed to recover the original text.",
        ])
        for index in range(0, min(len(encrypted), 64), 16):
            block = encrypted[index:index+16]
            table.append({
                "char": f"Block {index//16 + 1}",
                "value_before": block.hex(),
                "formula": "CBC: AES_D(C_i) XOR C_{i-1}",
                "value_after": padded[index:index+16].hex(),
                "output": padded[index:index+16].hex(),
            })
        meta = {"cipher": "ASA/AES", "mode": "AES-128-CBC", "iv_hex": iv.hex(), "key_hash_preview": key_hash.hex()[:32]}
    else:
        raise CryptoError("AES/ASA supports encrypt and decrypt actions.")

    return CryptoResponse(result, steps, table, warnings, meta)


# ------------------------------ Dispatcher --------------------------------

def process_cipher(cipher: str, action: str, text: str, keys: Dict[str, Any]) -> CryptoResponse:
    cipher = clean_key(cipher).lower()
    action = clean_key(action).lower()
    text = text or ""

    allowed_actions = {"encrypt", "decrypt", "sign", "verify"}
    if action not in allowed_actions:
        raise CryptoError("Invalid action selected.")

    if cipher == "caesar":
        if action not in {"encrypt", "decrypt"}:
            raise CryptoError("Caesar Cipher supports encrypt/decrypt only.")
        return caesar_cipher(text, action, keys)
    if cipher == "affine":
        if action not in {"encrypt", "decrypt"}:
            raise CryptoError("Affine Cipher supports encrypt/decrypt only.")
        return affine_cipher(text, action, keys)
    if cipher == "vigenere":
        if action not in {"encrypt", "decrypt"}:
            raise CryptoError("Vigenere Cipher supports encrypt/decrypt only.")
        return vigenere_cipher(text, action, keys)
    if cipher == "substitution":
        if action not in {"encrypt", "decrypt"}:
            raise CryptoError("Substitution Cipher supports encrypt/decrypt only.")
        return substitution_cipher(text, action, keys)
    if cipher == "rsa":
        if action not in {"encrypt", "decrypt"}:
            raise CryptoError("RSA option supports encrypt/decrypt only in this educational app.")
        return rsa_cipher(text, action, keys)
    if cipher == "dsa":
        return dsa_process(text, action, keys)
    if cipher in {"asa", "aes", "asa_aes"}:
        if action not in {"encrypt", "decrypt"}:
            raise CryptoError("ASA/AES supports encrypt/decrypt only.")
        return asa_aes_cipher(text, action, keys)

    raise CryptoError("Unknown cipher selected.")
