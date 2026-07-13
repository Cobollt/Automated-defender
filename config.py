from pathlib import Path


class AppConfig:
    APP_NAME = "AntiArchiveScanner"

    BASE_DIR = Path(__file__).resolve().parent

    DOWNLOADS_DIR = Path.home() / "Downloads"
    LOGS_DIR = BASE_DIR / "logs"
    REPORTS_DIR = BASE_DIR / "reports"
    QUARANTINE_DIR = BASE_DIR / "quarantine"

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

    AUTOSTART_STDOUT_LOG = LOGS_DIR / "autostart_stdout.log"
    AUTOSTART_STDERR_LOG = LOGS_DIR / "autostart_stderr.log"

    REPORT_HISTORY_FILE = REPORTS_DIR / "scan_history.jsonl"
    ACTION_HISTORY_FILE = REPORTS_DIR / "action_history.jsonl"

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
    def prepare_dirs(cls) -> None:
        cls.LOGS_DIR.mkdir(parents=True, exist_ok=True)
        cls.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        cls.QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)