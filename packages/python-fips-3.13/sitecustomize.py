"""sitecustomize for the python-fips 3.13 image: multiprocessing starts
processes with forkserver by default, and lists it first among the start
methods, as Python 3.14 does.

The gofips provider runs in a Go runtime inside the process, and Go does
not support fork() without exec: a forked child that uses crypto can hang
on a lock the runtime held at the fork. forkserver forks from a fresh
server process instead. multiprocessing.set_start_method("fork") and
get_context("fork") still choose fork explicitly.

Nothing is imported at startup: a one-shot finder sets the default as
multiprocessing.context loads, or it is set in place if the module is
already loaded (a .pth file runs before this).
"""
import sys


def _prefer_forkserver(context):
    dc = context._default_context
    if "forkserver" not in context._concrete_contexts or dc._actual_context is not None:
        return  # no forkserver here, or a start method was already chosen
    dc._default_context = context._concrete_contexts["forkserver"]
    get_all = dc.get_all_start_methods

    def get_all_start_methods():
        methods = get_all()
        return ["forkserver"] + [m for m in methods if m != "forkserver"]

    dc.get_all_start_methods = get_all_start_methods
    # multiprocessing exports the default context's bound methods.
    mp = sys.modules.get("multiprocessing")
    if mp is not None and hasattr(mp, "get_all_start_methods"):
        mp.get_all_start_methods = get_all_start_methods


class _ForkserverDefault:
    @classmethod
    def find_spec(cls, name, path=None, target=None):
        if name != "multiprocessing.context":
            return None
        sys.meta_path.remove(cls)
        import importlib.util
        spec = importlib.util.find_spec(name)
        if spec is None or spec.loader is None:
            return spec
        exec_module = spec.loader.exec_module

        def load(module):
            exec_module(module)
            _prefer_forkserver(module)

        spec.loader.exec_module = load
        return spec


if "multiprocessing.context" in sys.modules:
    _prefer_forkserver(sys.modules["multiprocessing.context"])
else:
    sys.meta_path.insert(0, _ForkserverDefault)
