"""
Structured logging compatibility for stdlib loggers.
==================================================

Several SMSLYCLOUD services mix ``structlog``-style calls
(``logger.info("event", key=value)``) with the standard library
``logging`` module. The stdlib logger rejects unknown keyword arguments:

    TypeError: Logger._log() got an unexpected keyword argument 'request_id'

That exception is raised *inside* the call, so a single structured log
line aborts the surrounding block. In practice it silently disabled:

* the gateway watchdog reconciliation loop (stuck requests never closed), and
* the policy service audit client (every audit event dropped).

``KwArgLogger`` accepts those keywords, folds them into the rendered
message and attaches them to the record as ``extra`` so JSON formatters can
pick them up. Installing it is a no-op for services that only use
``structlog`` and is safe for third-party loggers: unknown keywords are
simply rendered instead of raising.

Usage (must run before the affected modules create their loggers)::

    from smsly_core.structured_logging import install_structured_logger
    install_structured_logger()
"""

from __future__ import annotations

import logging
from typing import Any, Dict

# LogRecord attributes that must never be overwritten via `extra` —
# logging raises KeyError("Attempt to overwrite %r in LogRecord") for them.
_RESERVED_RECORD_ATTRS = frozenset(
    {
        "args", "asctime", "created", "exc_info", "exc_text", "filename",
        "funcName", "levelname", "levelno", "lineno", "message", "module",
        "msecs", "msg", "name", "pathname", "process", "processName",
        "relativeCreated", "stack_info", "taskName", "thread", "threadName",
    }
)


class KwArgLogger(logging.Logger):
    """A stdlib logger that accepts structlog-style keyword arguments."""

    def _log(  # type: ignore[override]
        self,
        level: int,
        msg: Any,
        args: Any,
        exc_info: Any = None,
        extra: Any = None,
        stack_info: bool = False,
        stacklevel: int = 1,
        **kwargs: Any,
    ) -> None:
        if kwargs:
            # 1) Render the keywords into the message so nothing is lost
            #    even with a plain text formatter.
            try:
                rendered = " ".join(f"{k}={v!r}" for k, v in kwargs.items())
                if isinstance(msg, str):
                    msg = f"{msg} {rendered}"
                else:
                    msg = f"{msg} {rendered}"
            except Exception:
                pass

            # 2) Attach them as record attributes for JSON formatters,
            #    skipping the reserved LogRecord names.
            try:
                _extra: Dict[str, Any] = dict(extra or {})
                for k, v in kwargs.items():
                    if k not in _RESERVED_RECORD_ATTRS and k not in _extra:
                        _extra[k] = v
                extra = _extra
            except Exception:
                pass

        super()._log(
            level,
            msg,
            args,
            exc_info=exc_info,
            extra=extra,
            stack_info=stack_info,
            stacklevel=stacklevel,
        )


_installed = False


def install_structured_logger() -> None:
    """Install :class:`KwArgLogger` for every logger (existing and future).

    Idempotent. Existing logger instances are re-classed in place so the
    fix applies even when the module was imported before the installer
    ran.
    """
    global _installed
    if _installed:
        return

    current = logging.getLoggerClass()
    if not issubclass(current, KwArgLogger):
        logging.setLoggerClass(KwArgLogger)

    # Re-class loggers that already exist (module-level getLogger calls).
    manager = logging.Logger.manager
    for name in list(manager.loggerDict.keys()):
        lg = manager.loggerDict.get(name)
        if isinstance(lg, logging.Logger) and not isinstance(lg, KwArgLogger):
            try:
                lg.__class__ = KwArgLogger
            except TypeError:  # pragma: no cover - exotic Logger subclasses
                pass

    _installed = True


__all__ = ["KwArgLogger", "install_structured_logger"]
