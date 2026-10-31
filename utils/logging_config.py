import logging
import sys
from pathlib import Path
from datetime import datetime


def setup_logging(case_dir: Path | None = None, level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger("polaris")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    if logger.handlers:
        return logger

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.WARNING)
    console_fmt = logging.Formatter("[%(levelname)s] %(message)s")
    console.setFormatter(console_fmt)
    logger.addHandler(console)

    if case_dir:
        log_dir = case_dir / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_handler = logging.FileHandler(
            log_dir / f"polaris_{ts}.log",
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_fmt = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_fmt)
        logger.addHandler(file_handler)

    return logger
