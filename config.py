from pathlib import Path


class AppConfig:
    APP_NAME = "AntiArchiveScanner"

    BASE_DIR = Path(__file__).resolve().parent

    DOWNLOADS_DIR = Path.home() / "Downloads"
    LOGS_DIR = BASE_DIR / "logs"
    REPORTS_DIR = BASE_DIR / "reports"
    QUARANTINE_DIR = BASE_DIR / "quarantine"

    FILE_READY_TIMEOUT = 30
    FILE_READY_CHECK_INTERVAL = 1

    MAX_EXTRACTED_SIZE_MB = 500
    MAX_FILES_IN_ARCHIVE = 1000
    MAX_ARCHIVE_DEPTH = 3

    @classmethod
    def prepare_dirs(cls) -> None:
        cls.LOGS_DIR.mkdir(exist_ok=True)
        cls.REPORTS_DIR.mkdir(exist_ok=True)
        cls.QUARANTINE_DIR.mkdir(exist_ok=True)