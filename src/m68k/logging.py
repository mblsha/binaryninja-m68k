from __future__ import annotations

import sys

# This repository includes `logging.py` for Binary Ninja logging helpers. When the
# repo root is on `sys.path`, this filename can shadow the stdlib `logging`
# module. If imported as top-level `logging`, delegate to the real stdlib module
# so tools like `pytest` keep working.
if __name__ == "logging":
    import importlib.util
    import sysconfig
    from pathlib import Path

    stdlib_path = sysconfig.get_path("stdlib")
    if not stdlib_path:
        raise ImportError("Unable to locate stdlib path for `logging`")

    stdlib_logging = Path(stdlib_path) / "logging" / "__init__.py"
    spec = importlib.util.spec_from_file_location("logging", stdlib_logging)
    if spec is None or spec.loader is None:
        raise ImportError("Unable to load stdlib `logging` module spec")

    module = importlib.util.module_from_spec(spec)
    sys.modules[__name__] = module
    spec.loader.exec_module(module)
    globals().update(module.__dict__)
else:
    import logging as _py_logging

    try:
        import binaryninja  # type: ignore[import-not-found]
    except ImportError:  # pragma: no cover
        binaryninja = None  # type: ignore[assignment]

    __module__ = sys.modules[__name__]

    _bn_logger = getattr(binaryninja, "Logger", None) if binaryninja is not None else None
    if _bn_logger is not None:
        __logger = _bn_logger(0, __module__.__name__)

        def log(level: object, message: object) -> None:
            __logger.log(level, str(message))

        def log_debug(message: object) -> None:
            __logger.log_debug(str(message))

        def log_info(message: object) -> None:
            __logger.log_info(str(message))

        def log_warn(message: object) -> None:
            __logger.log_warn(str(message))

        def log_error(message: object) -> None:
            __logger.log_error(str(message))

        def log_alert(message: object) -> None:
            __logger.log_alert(str(message))
    else:
        __logger = _py_logging.getLogger(__module__.__name__)

        def log(level: int, message: object) -> None:
            __logger.log(level, "%s", message)

        def log_debug(message: object) -> None:
            __logger.debug("%s", message)

        def log_info(message: object) -> None:
            __logger.info("%s", message)

        def log_warn(message: object) -> None:
            __logger.warning("%s", message)

        def log_error(message: object) -> None:
            __logger.error("%s", message)

        def log_alert(message: object) -> None:
            __logger.critical("%s", message)
