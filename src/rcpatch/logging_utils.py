"""Logging helpers for RCPatch modules."""

from __future__ import annotations

import logging
from typing import Optional, Union


def configure_logging(level: Union[int, str] = logging.INFO) -> None:
    """Configure root logging once for library and CLI use."""
    root_logger = logging.getLogger()
    if root_logger.handlers:
        root_logger.setLevel(level)
        return

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


def get_logger(name: str, level: Optional[Union[int, str]] = None) -> logging.Logger:
    """Return a module logger, optionally adjusting its level."""
    logger = logging.getLogger(name)
    if level is not None:
        logger.setLevel(level)
    return logger
