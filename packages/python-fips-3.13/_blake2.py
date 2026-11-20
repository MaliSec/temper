"""Stand-in for CPython's built-in BLAKE2 module in the python-fips image.

BLAKE2 is not FIPS-approved and the Go Cryptographic Module does not provide
it. CPython implements it itself, outside OpenSSL, so python-fips replaces
that module: hashlib still imports cleanly, and any BLAKE2 use fails.
"""


def _unavailable(*args, **kwargs):
    raise ValueError("BLAKE2 is not available in python-fips: it is not a FIPS-approved hash")


blake2b = _unavailable
blake2s = _unavailable
