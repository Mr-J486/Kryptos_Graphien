import secrets
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from Hashing.SHA256 import generate_hash as _sha256_hex


def _sha256_bytes(data: bytes) -> bytes:
    return bytes.fromhex(_sha256_hex(data))


#---------------------------------------------------------
#  Curve Registry
#---------------------------------------------------------
_CURVES = {
    "secp256r1": {
        "P":  0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        "A":  0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
        "B":  0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        "GX": 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        "GY": 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
        "N":  0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    },
    "secp256k1": {
        "P":  0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
        "A":  0,
        "B":  7,
        "GX": 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        "GY": 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
        "N":  0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    },
}

_DEFAULT_CURVE = "secp256r1"
_INF = None


def _get_curve(curve_name: str) -> dict:
    if curve_name not in _CURVES:
        raise ValueError(
            f"Unknown curve '{curve_name}'. "
            f"Supported curves: {', '.join(_CURVES.keys())}"
        )
    return _CURVES[curve_name]

_c  = _CURVES[_DEFAULT_CURVE]
_P  = _c["P"]; _A = _c["A"]; _B = _c["B"]
_GX = _c["GX"]; _GY = _c["GY"]; _N = _c["N"]
_G  = (_GX, _GY)


#-------------------------------------------------------
#  Internal Curve Arithmetic
#-------------------------------------------------------

def _mod_inv(a: int, m: int) -> int:
    return pow(a, -1, m)


def _point_add(P1, P2, p, a):
    if P1 is _INF:
        return P2
    if P2 is _INF:
        return P1
    x1, y1 = P1
    x2, y2 = P2
    if x1 == x2 and (y1 + y2) % p == 0:
        return _INF
    if P1 == P2:
        lam = (3 * x1 * x1 + a) * _mod_inv(2 * y1, p) % p
    else:
        lam = (y2 - y1) * _mod_inv(x2 - x1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def _scalar_mult(k: int, point, p, a):
    result = _INF
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend, p, a)
        addend = _point_add(addend, addend, p, a)
        k >>= 1
    return result


def _hash_message(message: bytes, n: int) -> int:
    return int.from_bytes(_sha256_bytes(message), 'big') % n


def generate_keypair(curve_name: str = _DEFAULT_CURVE) -> tuple:
    c = _get_curve(curve_name)
    G = (c["GX"], c["GY"])
    private_key = secrets.randbelow(c["N"] - 1) + 1
    public_key  = _scalar_mult(private_key, G, c["P"], c["A"])
    return private_key, public_key


def is_valid_public_key(public_key: tuple, curve_name: str = _DEFAULT_CURVE) -> bool:
    if public_key is _INF:
        return False
    c = _get_curve(curve_name)
    p, a, b, n = c["P"], c["A"], c["B"], c["N"]
    x, y = public_key
    if not (0 <= x < p and 0 <= y < p):
        return False
    if (y * y - x * x * x - a * x - b) % p != 0:
        return False
    if _scalar_mult(n, public_key, p, a) is not _INF:
        return False
    return True


def ecdh_shared_secret(private_key: int, peer_public_key: tuple,
                       curve_name: str = _DEFAULT_CURVE) -> bytes:
    c = _get_curve(curve_name)
    shared_point = _scalar_mult(private_key, peer_public_key, c["P"], c["A"])
    if shared_point is _INF:
        raise ValueError("Shared point is the point at infinity — invalid key pair.")
    return _sha256_bytes(shared_point[0].to_bytes(32, 'big'))


def ecdsa_sign(message: bytes, private_key: int,
               curve_name: str = _DEFAULT_CURVE) -> tuple:
    c = _get_curve(curve_name)
    p, a, n = c["P"], c["A"], c["N"]
    G = (c["GX"], c["GY"])
    z = _hash_message(message, n)
    while True:
        k = secrets.randbelow(n - 1) + 1
        point = _scalar_mult(k, G, p, a)
        r = point[0] % n
        if r == 0:
            continue
        s = _mod_inv(k, n) * (z + r * private_key) % n
        if s == 0:
            continue
        return (r, s)


def ecdsa_verify(message: bytes, signature: tuple, public_key: tuple,
                 curve_name: str = _DEFAULT_CURVE) -> bool:
    c = _get_curve(curve_name)
    p, a, n = c["P"], c["A"], c["N"]
    G = (c["GX"], c["GY"])
    r, s = signature
    if not (1 <= r < n and 1 <= s < n):
        return False
    z  = _hash_message(message, n)
    w  = _mod_inv(s, n)
    u1 = z * w % n
    u2 = r * w % n
    point = _point_add(
        _scalar_mult(u1, G, p, a),
        _scalar_mult(u2, public_key, p, a),
        p, a
    )
    if point is _INF:
        return False
    return point[0] % n == r













































# ---------------------------------------------
#  Encoding helpers
# ---------------------------------------

def private_key_to_hex(private_key: int) -> str:
    return hex(private_key)[2:].zfill(64)


def public_key_to_hex(public_key: tuple) -> str:
    x, y = public_key
    return f"04{hex(x)[2:].zfill(64)}{hex(y)[2:].zfill(64)}"


def public_key_to_compressed_hex(public_key: tuple) -> str:
    x, y = public_key
    prefix = "02" if y % 2 == 0 else "03"
    return f"{prefix}{hex(x)[2:].zfill(64)}"
