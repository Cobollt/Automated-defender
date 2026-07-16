import platform
import sys
from pathlib import Path


class AppConfig:
    APP_NAME = "AntiArchiveScanner"
    APP_DIRECTORY_NAME = "AntiArchiveScanner"

    SOURCE_DIR = Path(__file__).resolve().parent

    DOWNLOADS_DIR = Path.home() / "Downloads"

    DATA_DIR = (
        Path.home()
        / "Library"
        / "Application Support"
        / APP_DIRECTORY_NAME
        if platform.system() == "Darwin"
        else (
            Path.home()
            / "AppData"
            / "Local"
            / APP_DIRECTORY_NAME
            if platform.system() == "Windows"
            else Path.home() / f".{APP_DIRECTORY_NAME.lower()}"
        )
    )

    LOGS_DIR = DATA_DIR / "logs"
    REPORTS_DIR = DATA_DIR / "reports"
    QUARANTINE_DIR = DATA_DIR / "quarantine"

    FILE_READY_TIMEOUT = 60
    FILE_READY_CHECK_INTERVAL = 1
    FILE_STABLE_CHECKS_REQUIRED = 3

    MAX_EXTRACTED_SIZE_MB = 500
    MAX_FILES_IN_ARCHIVE = 1000
    MAX_ARCHIVE_DEPTH = 3
    MAX_COMPRESSION_RATIO = 100.0

    SYSTEM_SECURITY_TIMEOUT = 30

    QUARANTINE_METADATA_EXTENSION = ".json"
    QUARANTINE_FILE_EXTENSION = ".quarantine"

    AUTOSTART_TASK_NAME = "AntiArchiveScanner"
    MACOS_LAUNCH_AGENT_LABEL = "com.antiarchivescanner.agent"

    AUTOSTART_STDOUT_LOG = (
        LOGS_DIR / "autostart_stdout.log"
    )
    AUTOSTART_STDERR_LOG = (
        LOGS_DIR / "autostart_stderr.log"
    )

    REPORT_HISTORY_FILE = (
        REPORTS_DIR / "scan_history.jsonl"
    )
    ACTION_HISTORY_FILE = (
        REPORTS_DIR / "action_history.jsonl"
    )

    MAX_REPORT_FILES = 500
    REPORT_FILE_PREFIX = "scan"

    TEMP_DOWNLOAD_EXTENSIONS = {
        ".crdownload",
        ".part",
        ".download",
        ".tmp",
        ".partial",
    }

    @classmethod
    def is_frozen(cls) -> bool:
        return bool(
            getattr(sys, "frozen", False)
        )

    @classmethod
    def executable_path(cls) -> Path:
        return Path(sys.executable).resolve()

    @classmethod
    def application_path(cls) -> Path:
        if cls.is_frozen():
            return cls.executable_path()

        return (cls.SOURCE_DIR / "app.py").resolve()

    @classmethod
    def prepare_dirs(cls) -> None:
        for directory in (
            cls.DATA_DIR,
            cls.LOGS_DIR,
            cls.REPORTS_DIR,
            cls.QUARANTINE_DIR,
        ):
            directory.mkdir(
                parents=True,
                exist_ok=True,
            )