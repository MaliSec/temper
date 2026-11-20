"""HMAC (RFC 2104) for the python-fips image.

Replaces the standard library's hmac module: every HMAC is computed by the
gofips provider's HMAC (_hashlib.hmac_digest, OpenSSL's EVP_MAC), which runs
in the Go Cryptographic Module and refuses keys under 112 bits and
non-approved digests. The standard module would also compute HMAC itself
(in pure Python, in its built-in HMAC, or through OpenSSL's legacy HMAC_CTX)
in cases OpenSSL refuses or it does not hand to OpenSSL.

The message is kept until digest() is called, so an HMAC object holds its
whole input in memory.
"""
import _hashlib

try:
    compare_digest = _hashlib.compare_digest
except AttributeError:  # pragma: no cover
    from _operator import _compare_digest as compare_digest

trans_5C = bytes((x ^ 0x5C) for x in range(256))
trans_36 = bytes((x ^ 0x36) for x in range(256))

# The size of the digests returned by HMAC depends on the underlying
# hashing module used.
digest_size = None

_hmac_digest = _hashlib.hmac_digest


def _refused(reason):
    return ValueError(f"HMAC refused in python-fips: {reason}")


def _digest_name(digestmod):
    """The OpenSSL name of a digestmod: a name, or a hashlib constructor."""
    if isinstance(digestmod, str):
        return digestmod
    ctor = getattr(digestmod, "new", digestmod)
    if callable(ctor):
        try:
            h = ctor()
        except Exception:
            h = None
        if h is not None and type(h).__module__ == "_hashlib":
            return h.name
    raise _refused("digestmod must be a hash name such as 'sha256' or a hashlib constructor")


def _check(key, digestmod):
    if not digestmod:
        raise TypeError("Missing required argument 'digestmod'.")
    name = _digest_name(digestmod)
    try:
        _hmac_digest(key, b"", name)
    except ValueError as e:
        raise _refused(str(e) if str(e) and "no reason" not in str(e)
                       else f"{name} with a {len(key) * 8}-bit key (keys of 112 bits or more, SHA-2 or SHA-3)") from None
    return name


class HMAC:
    """RFC 2104 HMAC class, computed by the gofips provider."""

    blocksize = 64  # 512-bit HMAC; kept for compatibility

    __slots__ = ("_key", "_digestmod", "_buf", "digest_size", "block_size", "name")

    def __init__(self, key, msg=None, digestmod=''):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError(f"key: expected bytes or bytearray, but got {type(key).__name__!r}")
        self._digestmod = _check(key, digestmod)
        h = _hashlib.new(self._digestmod)
        self._key = bytes(key)
        self._buf = bytearray()
        self.name = "hmac-" + h.name
        self.digest_size = h.digest_size
        self.block_size = h.block_size
        if msg is not None:
            self.update(msg)

    def update(self, msg):
        self._buf += msg

    def copy(self):
        other = object.__new__(HMAC)
        for attr in HMAC.__slots__:
            setattr(other, attr, getattr(self, attr))
        other._buf = bytearray(self._buf)
        return other

    def digest(self):
        return _hmac_digest(self._key, bytes(self._buf), self._digestmod)

    def hexdigest(self):
        return self.digest().hex()


def new(key, msg=None, digestmod=''):
    """Create a new hashing object and return it."""
    return HMAC(key, msg, digestmod)


def digest(key, msg, digest):
    """Fast inline implementation of HMAC."""
    name = _check(key, digest)
    return _hmac_digest(key, msg, name)


def _hashlib_hmac_new(key, msg=b"", digestmod=None):
    return HMAC(key, msg, digestmod)


# _hashlib.hmac_new uses OpenSSL's legacy HMAC_CTX, which builds HMAC in
# libcrypto from digest calls and applies no key-length check.
_hashlib.hmac_new = _hashlib_hmac_new
