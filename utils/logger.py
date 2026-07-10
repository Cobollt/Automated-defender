import logging
from logging.handlers import RotatingFileHandler

from config import AppConfig


def setup_logger() -> logging.Logger:
    AppConfig.prepare_dirs()

    logger = logging.getLogger(AppConfig.APP_NAME)
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger

    log_file = AppConfig.LOGS_DIR / "scanner.log"

    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=1024 * 1024,
        backupCount=5,
        encoding="utf-8"
    )

    console_handler = logging.StreamHandler()

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger