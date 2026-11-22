
"""Logging setup helpers for the assessment application."""

import logging
from pathlib import Path


_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


def get_logger(name: str = "redteam") -> logging.Logger:
    """Return a named logger without changing global logging configuration."""
    return logging.getLogger(name)


def configure_logging(
    level: str | int = logging.INFO,
    log_file: str | Path | None = None,
    console: bool = True,
) -> logging.Logger:
    """Configure the application logger and return it.

    Repeated calls reuse equivalent handlers instead of duplicating output.
    File-system and configuration errors are allowed to propagate to callers.
    """
    if isinstance(level, str):
        resolved_level = logging.getLevelName(level.upper())
        if not isinstance(resolved_level, int):
            raise ValueError(f"Unknown logging level: {level}")
    elif isinstance(level, int) and not isinstance(level, bool):
        resolved_level = level
    else:
        raise TypeError("level must be a logging level name or integer")

    logger = get_logger()
    logger.setLevel(resolved_level)
    logger.propagate = False

    formatter = logging.Formatter(_FORMAT)
    handler_specs: list[tuple[str, str | None]] = []
    if console:
        handler_specs.append(("console", None))
    if log_file is not None:
        file_path = Path(log_file)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        handler_specs.append(("file", str(file_path.resolve())))

    for kind, destination in handler_specs:
        handler_key = (kind, destination)
        if any(
            getattr(handler, "_redteam_handler_key", None) == handler_key
            for handler in logger.handlers
        ):
            continue

        handler: logging.Handler
        if kind == "console":
            handler = logging.StreamHandler()
        else:
            handler = logging.FileHandler(destination, encoding="utf-8")
        handler.setFormatter(formatter)
        setattr(handler, "_redteam_handler_key", handler_key)
        logger.addHandler(handler)

    return logger
