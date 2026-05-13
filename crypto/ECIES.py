import hmac as _hmac
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from Hashing.SHA256 import generate_hash as _sha256_hex
from AES.aes import aes_cbc_encrypt, aes_cbc_decrypt
from crypto.ECC import (
    generate_keypair,
    ecdh_shared_secret,
    is_valid_public_key,
)


class _SHA256Digestmod:
    digest_size = 32   
    block_size  = 64   

    def __init__(self, data: bytes = b""):
        self._data = bytearray(data)

    def update(self, data: bytes) -> None:
        self._data += data

    def digest(self) -> bytes:
        return bytes.fromhex(_sha256_hex(bytes(self._data)))

    def hexdigest(self) -> str:
        return _sha256_hex(bytes(self._data))

    def copy(self) -> "_SHA256Digestmod":
        return _SHA256Digestmod(bytes(self._data))

    def __call__(self, data: bytes = b"") -> "_SHA256Digestmod":
        return _SHA256Digestmod(data)



_sha256 = _SHA256Digestmod()


# -------------------------------------------------------
_AES_KEY_LEN = 16   # bytes AES-128 
_MAC_KEY_LEN = 32   # bytes HMAC-SHA256
_IV_LEN      = 16   # bytes AES block size
_TAG_LEN     = 32   # bytes HMAC-SHA256 output
_POINT_LEN   = 65   # bytes uncompressed EC point 04||x||y


# --------------------------------------
#  Key Derivation  (HKDF-SHA256)
# ---------------------------

def _hkdf(ikm: bytes, length: int, info: bytes = b"ECIES") -> bytes:
    # Extract
    prk = _hmac.new(bytes(32), ikm, _sha256).digest()
    # Expand
    output, t, i = b"", b"", 1
    while len(output) < length:
        t = _hmac.new(prk, t + info + bytes([i]), _sha256).digest()
        output += t
        i += 1
    return output[:length]


def _derive_keys(shared_secret: bytes):
    km = _hkdf(shared_secret, _AES_KEY_LEN + _MAC_KEY_LEN)
    return km[:_AES_KEY_LEN], km[_AES_KEY_LEN:]


# ----------------------------------------------
#  Point Encoding
# ------------------

def _point_to_bytes(pt) -> bytes:
    x, y = pt
    return b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')


def _bytes_to_point(data: bytes):
    if len(data) != 65 or data[0] != 0x04:
        raise ValueError("Invalid EC point encoding")
    return (int.from_bytes(data[1:33], 'big'),
            int.from_bytes(data[33:65], 'big'))


# ---------------------------------------------------------
#  HMAC
# -----------------

def _mac(key: bytes, iv: bytes, ct: bytes) -> bytes:
    return _hmac.new(key, iv + ct, _sha256).digest()


# --------------------------------------------------------------
#  Bundle  R(65) | IV(16) | ctLen(4) | ciphertext | tag(32)
# --------------------------------------------------------------

def _pack(R, iv: bytes, ct: bytes, tag: bytes) -> bytes:
    return _point_to_bytes(R) + iv + len(ct).to_bytes(4, 'big') + ct + tag


def _unpack(bundle: bytes):
    min_len = _POINT_LEN + _IV_LEN + 4 + 16 + _TAG_LEN
    if len(bundle) < min_len:
        raise ValueError("Bundle too short")
    off = 0
    R   = _bytes_to_point(bundle[off:off+_POINT_LEN]); off += _POINT_LEN
    iv  = bundle[off:off+_IV_LEN];                      off += _IV_LEN
    ct_len = int.from_bytes(bundle[off:off+4], 'big');  off += 4
    ct  = bundle[off:off+ct_len];                        off += ct_len
    tag = bundle[off:off+_TAG_LEN]
    if len(tag) != _TAG_LEN:
        raise ValueError("Truncated tag in bundle")
    return R, iv, ct, tag


#---------------------------------------------------------------------------

def ecies_encrypt(plaintext: bytes, recipient_pub) -> bytes:
  
    if not is_valid_public_key(recipient_pub):
        raise ValueError("Invalid recipient public key")

    eph_priv, eph_pub = generate_keypair()                            # Step 1
    shared             = ecdh_shared_secret(eph_priv, recipient_pub)  # Step 2
    aes_key, mac_key   = _derive_keys(shared)                         # Step 3

    iv         = os.urandom(_IV_LEN)
    ciphertext = aes_cbc_encrypt(plaintext, aes_key, iv)              # Step 4  
    tag        = _mac(mac_key, iv, ciphertext)                        # Step 5

    return _pack(eph_pub, iv, ciphertext, tag)                        # Step 6


def ecies_decrypt(bundle: bytes, recipient_priv: int) -> bytes:

    R, iv, ct, tag     = _unpack(bundle)

    if not is_valid_public_key(R):
        raise ValueError("Invalid ephemeral public key")
    shared             = ecdh_shared_secret(recipient_priv, R)
    aes_key, mac_key   = _derive_keys(shared)

    expected = _mac(mac_key, iv, ct)
    if not _hmac.compare_digest(expected, tag):
        raise ValueError("MAC verification failed — message tampered or wrong key")

    return aes_cbc_decrypt(ct, aes_key, iv)                    


# ---------------------------wrappers---------------------------------

def ecies_encrypt_str(msg: str, pub, enc='utf-8') -> bytes:
    return ecies_encrypt(msg.encode(enc), pub)


def ecies_decrypt_str(bundle: bytes, priv: int, enc='utf-8') -> str:
    return ecies_decrypt(bundle, priv).decode(enc)


def bundle_to_hex(b: bytes) -> str:   return b.hex()
def bundle_from_hex(s: str)  -> bytes: return bytes.fromhex(s)