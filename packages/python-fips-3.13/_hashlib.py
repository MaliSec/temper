"""_hashlib for the python-fips image: CPython's OpenSSL module, with
hmac_new computed by the gofips provider.

The extension's hmac_new uses OpenSSL's legacy HMAC_CTX, which builds HMAC
in libcrypto from digest calls and applies no key-length check. This module
loads the extension and exports everything from it, with hmac_new replaced
by the python-fips hmac module's, from the first import.
"""
import importlib.machinery as _machinery
import importlib.util as _util
import os as _os


def _load():
    d = _os.path.join(_os.path.dirname(__file__), "lib-dynload")
    for suffix in _machinery.EXTENSION_SUFFIXES:
        path = _os.path.join(d, "_hashlib" + suffix)
        if _os.path.exists(path):
            spec = _util.spec_from_file_location(
                "_hashlib", path, loader=_machinery.ExtensionFileLoader("_hashlib", path))
            module = _util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
    raise ImportError("python-fips: the _hashlib extension is missing")


_ext = _load()
globals().update({k: v for k, v in vars(_ext).items() if not k.startswith("__")})
del _load


def hmac_new(key, msg=b"", digestmod=None):
    import hmac
    return hmac.HMAC(key, msg, digestmod)
