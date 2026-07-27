import os
import platform
import sys
import tempfile
from pathlib import Path


class AppConfig:
    APP_NAME = "AntiArchiveScanner"
    APP_DIRECTORY_NAME = "AntiArchiveScanner"

    SOURCE_DIR = Path(__file__).resolve().parent

    # ---------------------------------------------------------
    # Platform
    # ---------------------------------------------------------

    PLATFORM = platform.system()

    IS_WINDOWS = PLATFORM == "Windows"
    IS_MACOS = PLATFORM == "Darwin"
    IS_LINUX = PLATFORM == "Linux"

    # ---------------------------------------------------------
    # User directories
    # ---------------------------------------------------------

    HOME_DIR = Path.home()

    DOWNLOADS_DIR = HOME_DIR / "Downloads"

    if IS_MACOS:
        DATA_DIR = (
            HOME_DIR
            / "Library"
            / "Application Support"
            / APP_DIRECTORY_NAME
        )

    elif IS_WINDOWS:
        DATA_DIR = Path(
            os.environ.get(
                "LOCALAPPDATA",
                HOME_DIR
                / "AppData"
                / "Local",
            )
        ) / APP_DIRECTORY_NAME

    else:
        DATA_DIR = (
            HOME_DIR
            / f".{APP_DIRECTORY_NAME.lower()}"
        )

    LOGS_DIR = DATA_DIR / "logs"

    REPORTS_DIR = DATA_DIR / "reports"

    QUARANTINE_DIR = (
        DATA_DIR / "quarantine"
    )

    TEMP_DIR = (
        Path(tempfile.gettempdir())
        / "anti_archive_scanner"
    )

    # ---------------------------------------------------------
    # History
    # ---------------------------------------------------------

    REPORT_HISTORY_FILE = (
        REPORTS_DIR
        / "scan_history.jsonl"
    )

    ACTION_HISTORY_FILE = (
        REPORTS_DIR
        / "action_history.jsonl"
    )

    # ---------------------------------------------------------
    # Downloads watcher
    # ---------------------------------------------------------

    FILE_READY_TIMEOUT = 60.0

    FILE_READY_CHECK_INTERVAL = 1.0

    FILE_STABLE_CHECKS_REQUIRED = 3

    TEMP_DOWNLOAD_EXTENSIONS = {
        ".crdownload",
        ".part",
        ".download",
        ".tmp",
        ".partial",
    }

    # ---------------------------------------------------------
    # File limits
    # ---------------------------------------------------------

    MAX_INPUT_FILE_SIZE_MB = 2_048

    # ---------------------------------------------------------
    # Archive extraction limits
    # ---------------------------------------------------------

    MAX_EXTRACTED_SIZE_MB = 500

    MAX_FILES_IN_ARCHIVE = 1_000

    MAX_ARCHIVE_DEPTH = 3

    MAX_COMPRESSION_RATIO = 100.0

    # ---------------------------------------------------------
    # Temporary extraction
    # ---------------------------------------------------------

    TEMP_DIRECTORY_PREFIX = (
        "anti_archive_scanner_"
    )

    TEMP_DIRECTORY_MAX_AGE_SECONDS = (
        24 * 60 * 60
    )

    # ---------------------------------------------------------
    # System security
    # ---------------------------------------------------------

    SYSTEM_SECURITY_TIMEOUT = 30.0

    # ---------------------------------------------------------
    # Quarantine
    # ---------------------------------------------------------

    QUARANTINE_METADATA_EXTENSION = (
        ".json"
    )

    QUARANTINE_FILE_EXTENSION = (
        ".quarantine"
    )

    # ---------------------------------------------------------
    # Reports
    # ---------------------------------------------------------

    MAX_REPORT_FILES = 500

    REPORT_FILE_PREFIX = "scan"

    # ---------------------------------------------------------
    # Autostart
    # ---------------------------------------------------------

    AUTOSTART_TASK_NAME = (
        "AntiArchiveScanner"
    )

    MACOS_LAUNCH_AGENT_LABEL = (
        "com.antiarchivescanner.agent"
    )

    AUTOSTART_STDOUT_LOG = (
        LOGS_DIR
        / "autostart_stdout.log"
    )

    AUTOSTART_STDERR_LOG = (
        LOGS_DIR
        / "autostart_stderr.log"
    )

    # ---------------------------------------------------------
    # Computed size limits
    # ---------------------------------------------------------

    @classmethod
    def max_input_file_size_bytes(
        cls,
    ) -> int:
        return (
            cls.MAX_INPUT_FILE_SIZE_MB
            * 1024
            * 1024
        )

    @classmethod
    def max_extracted_size_bytes(
        cls,
    ) -> int:
        return (
            cls.MAX_EXTRACTED_SIZE_MB
            * 1024
            * 1024
        )

    # ---------------------------------------------------------
    # Application location
    # ---------------------------------------------------------

    @classmethod
    def is_frozen(
        cls,
    ) -> bool:
        return bool(
            getattr(
                sys,
                "frozen",
                False,
            )
        )

    @classmethod
    def executable_path(
        cls,
    ) -> Path:
        return Path(
            sys.executable
        ).resolve()

    @classmethod
    def application_path(
        cls,
    ) -> Path:
        if cls.is_frozen():
            return (
                cls.executable_path()
            )

        return (
            cls.SOURCE_DIR
            / "app.py"
        ).resolve()

    @classmethod
    def application_directory(
        cls,
    ) -> Path:
        if cls.is_frozen():
            return (
                cls.executable_path()
                .parent
            )

        return cls.SOURCE_DIR

    # ---------------------------------------------------------
    # Directory preparation
    # ---------------------------------------------------------

    @classmethod
    def prepare_dirs(
        cls,
    ) -> None:
        directories = (
            cls.DATA_DIR,
            cls.LOGS_DIR,
            cls.REPORTS_DIR,
            cls.QUARANTINE_DIR,
            cls.TEMP_DIR,
        )

        for directory in directories:
            directory.mkdir(
                parents=True,
                exist_ok=True,
            )

    # ---------------------------------------------------------
    # Validation
    # ---------------------------------------------------------

    @classmethod
    def validate(
        cls,
    ) -> None:
        cls._validate_positive_number(
            "FILE_READY_TIMEOUT",
            cls.FILE_READY_TIMEOUT,
        )

        cls._validate_positive_number(
            "FILE_READY_CHECK_INTERVAL",
            cls.FILE_READY_CHECK_INTERVAL,
        )

        cls._validate_positive_integer(
            "FILE_STABLE_CHECKS_REQUIRED",
            cls.FILE_STABLE_CHECKS_REQUIRED,
        )

        cls._validate_positive_integer(
            "MAX_INPUT_FILE_SIZE_MB",
            cls.MAX_INPUT_FILE_SIZE_MB,
        )

        cls._validate_positive_integer(
            "MAX_EXTRACTED_SIZE_MB",
            cls.MAX_EXTRACTED_SIZE_MB,
        )

        cls._validate_positive_integer(
            "MAX_FILES_IN_ARCHIVE",
            cls.MAX_FILES_IN_ARCHIVE,
        )

        if (
            not isinstance(
                cls.MAX_ARCHIVE_DEPTH,
                int,
            )
            or cls.MAX_ARCHIVE_DEPTH < 0
        ):
            raise ValueError(
                "MAX_ARCHIVE_DEPTH "
                "must be an integer "
                "greater than or equal to zero."
            )

        cls._validate_positive_number(
            "MAX_COMPRESSION_RATIO",
            cls.MAX_COMPRESSION_RATIO,
        )

        cls._validate_positive_number(
            "SYSTEM_SECURITY_TIMEOUT",
            cls.SYSTEM_SECURITY_TIMEOUT,
        )

        cls._validate_positive_integer(
            "MAX_REPORT_FILES",
            cls.MAX_REPORT_FILES,
        )

        cls._validate_positive_integer(
            "TEMP_DIRECTORY_MAX_AGE_SECONDS",
            cls.TEMP_DIRECTORY_MAX_AGE_SECONDS,
        )

        if (
            cls.MAX_EXTRACTED_SIZE_MB
            > cls.MAX_INPUT_FILE_SIZE_MB
            * 100
        ):
            raise ValueError(
                "MAX_EXTRACTED_SIZE_MB "
                "is unreasonably large "
                "relative to "
                "MAX_INPUT_FILE_SIZE_MB."
            )

        if not cls.APP_NAME.strip():
            raise ValueError(
                "APP_NAME cannot be empty."
            )

        if (
            not cls
            .APP_DIRECTORY_NAME
            .strip()
        ):
            raise ValueError(
                "APP_DIRECTORY_NAME "
                "cannot be empty."
            )

        if (
            not cls
            .REPORT_FILE_PREFIX
            .strip()
        ):
            raise ValueError(
                "REPORT_FILE_PREFIX "
                "cannot be empty."
            )

        if (
            not cls
            .QUARANTINE_FILE_EXTENSION
            .startswith(".")
        ):
            raise ValueError(
                "QUARANTINE_FILE_EXTENSION "
                "must start with '.'."
            )

        if (
            not cls
            .QUARANTINE_METADATA_EXTENSION
            .startswith(".")
        ):
            raise ValueError(
                "QUARANTINE_METADATA_EXTENSION "
                "must start with '.'."
            )

        if (
            not isinstance(
                cls.TEMP_DOWNLOAD_EXTENSIONS,
                set,
            )
            or not cls.TEMP_DOWNLOAD_EXTENSIONS
        ):
            raise ValueError(
                "TEMP_DOWNLOAD_EXTENSIONS "
                "must be a non-empty set."
            )

        for extension in (
            cls.TEMP_DOWNLOAD_EXTENSIONS
        ):
            if (
                not isinstance(
                    extension,
                    str,
                )
                or not extension.startswith(
                    "."
                )
            ):
                raise ValueError(
                    "Every temporary download "
                    "extension must be a string "
                    "starting with '.'."
                )

    # ---------------------------------------------------------
    # Internal validation helpers
    # ---------------------------------------------------------

    @staticmethod
    def _validate_positive_integer(
        name: str,
        value: int,
    ) -> None:
        if (
            not isinstance(
                value,
                int,
            )
            or isinstance(
                value,
                bool,
            )
            or value <= 0
        ):
            raise ValueError(
                f"{name} must be "
                "a positive integer."
            )

    @staticmethod
    def _validate_positive_number(
        name: str,
        value: int | float,
    ) -> None:
        if (
            isinstance(
                value,
                bool,
            )
            or not isinstance(
                value,
                (int, float),
            )
            or value <= 0
        ):
            raise ValueError(
                f"{name} must be "
                "a positive number."
            )