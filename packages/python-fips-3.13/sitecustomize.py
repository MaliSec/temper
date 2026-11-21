"""sitecustomize for the python-fips 3.13 image: multiprocessing starts
processes with forkserver by default, as Python 3.14 does.

The gofips provider runs in a Go runtime inside the process. A fork()ed
child that uses crypto while another thread of the parent was inside the
provider can block for ever on a lock that thread held. forkserver forks
from a fresh server process instead. multiprocessing.set_start_method()
and get_context("fork") still choose fork explicitly.

Nothing is imported until multiprocessing.context is: a one-shot finder
adjusts its default as it loads.
"""
import sys


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
            contexts = module._concrete_contexts
            if "forkserver" in contexts and module._default_context._actual_context is None:
                module._default_context = module.DefaultContext(contexts["forkserver"])

        spec.loader.exec_module = load
        return spec


sys.meta_path.insert(0, _ForkserverDefault)
