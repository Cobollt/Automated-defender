import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from application.reporting_service import ReportingService
from config import AppConfig
from domain.enums import RiskLevel
from domain.interfaces import (
    FileWatcherInterface,
    NotifierInterface,
    ScannerServiceInterface,
)
from domain.models import ScanResult
from utils.logger import setup_logger


DANGEROUS_RISK_LEVELS = {
    RiskLevel.HIGH,
    RiskLevel.CRITICAL,
}


class DownloadsEventHandler(FileSystemEventHandler):
    def __init__(
        self,
        scanner: ScannerServiceInterface,
        notifier: NotifierInterface,
        reporting_service: ReportingService,
        executor: ThreadPoolExecutor,
        on_scan_completed: Callable[[ScanResult], None],
    ) -> None:
        self._scanner = scanner
        self._notifier = notifier
        self._reporting_service = reporting_service
        self._executor = executor
        self._on_scan_completed = on_scan_completed
        self._logger = setup_logger()

        self._processing_files: set[Path] = set()
        self._processing_lock = threading.Lock()

    def on_created(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return

        self._schedule_file(Path(event.src_path))

    def on_moved(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return

        destination_path = getattr(
            event,
            "dest_path",
            None,
        )

        if destination_path:
            self._schedule_file(
                Path(destination_path)
            )

    def _schedule_file(
        self,
        file_path: Path,
    ) -> None:
        normalized_path = file_path.resolve()

        if self._should_ignore(
            normalized_path
        ):
            return

        if not self._try_mark_as_processing(
            normalized_path
        ):
            self._logger.debug(
                "File is already scheduled for scanning: %s",
                normalized_path,
            )
            return

        try:
            self._executor.submit(
                self._process_file,
                normalized_path,
            )

        except Exception:
            self._release_processing_file(
                normalized_path
            )
            raise

    def _try_mark_as_processing(
        self,
        file_path: Path,
    ) -> bool:
        normalized_path = file_path.resolve()

        with self._processing_lock:
            if (
                normalized_path
                in self._processing_files
            ):
                return False

            self._processing_files.add(
                normalized_path
            )

            return True

    def _release_processing_file(
        self,
        file_path: Path,
    ) -> None:
        normalized_path = file_path.resolve()

        with self._processing_lock:
            self._processing_files.discard(
                normalized_path
            )

    def _process_file(
        self,
        file_path: Path,
    ) -> None:
        normalized_path = file_path.resolve()

        try:
            self._logger.info(
                "Detected new file: %s",
                normalized_path,
            )

            if self._should_ignore(
                normalized_path
            ):
                return

            if not self._wait_until_file_ready(
                normalized_path
            ):
                self._logger.warning(
                    "File did not become ready: %s",
                    normalized_path,
                )
                return

            result = self._scanner.scan(
                normalized_path
            )

            report_path = (
                self._reporting_service
                .save_scan_result(
                    result
                )
            )

            if report_path is not None:
                self._logger.info(
                    "Report saved for %s: %s",
                    normalized_path,
                    report_path,
                )

            self._print_result(
                result
            )

            if (
                result.risk_level
                not in DANGEROUS_RISK_LEVELS
            ):
                self._logger.info(
                    "Scan completed without user action: "
                    "file=%s risk_level=%s risk_score=%s",
                    normalized_path,
                    result.risk_level.value,
                    result.risk_score,
                )
                return

            notification_sent = (
                self._notifier
                .notify_scan_result(
                    result
                )
            )

            if not notification_sent:
                self._logger.warning(
                    "System notification was not delivered for: %s",
                    normalized_path,
                )

            self._on_scan_completed(
                result
            )

        except Exception:
            self._logger.exception(
                "Unexpected error while processing file: %s",
                normalized_path,
            )

        finally:
            self._release_processing_file(
                normalized_path
            )

    def _should_ignore(
        self,
        file_path: Path,
    ) -> bool:
        if file_path.name.startswith("."):
            return True

        return (
            file_path.suffix.lower()
            in AppConfig.TEMP_DOWNLOAD_EXTENSIONS
        )

    def _wait_until_file_ready(
        self,
        file_path: Path,
    ) -> bool:
        previous_size: int | None = None
        stable_checks = 0

        deadline = (
            time.monotonic()
            + AppConfig.FILE_READY_TIMEOUT
        )

        while (
            time.monotonic()
            < deadline
        ):
            if (
                not file_path.exists()
                or not file_path.is_file()
            ):
                return False

            try:
                current_size = (
                    file_path.stat().st_size
                )

                with file_path.open("rb"):
                    pass

            except (
                OSError,
                PermissionError,
            ):
                stable_checks = 0

                time.sleep(
                    AppConfig
                    .FILE_READY_CHECK_INTERVAL
                )

                continue

            if (
                current_size
                == previous_size
            ):
                stable_checks += 1

            else:
                previous_size = (
                    current_size
                )
                stable_checks = 0

            if (
                stable_checks
                >= AppConfig
                .FILE_STABLE_CHECKS_REQUIRED
            ):
                return True

            time.sleep(
                AppConfig
                .FILE_READY_CHECK_INTERVAL
            )

        return False

    def _print_result(
        self,
        result: ScanResult,
    ) -> None:
        print()
        print(
            "=== Scan completed ==="
        )
        print(
            "File:",
            result.target_path,
        )
        print(
            "Status:",
            result.status.value,
        )
        print(
            "Risk level:",
            result.risk_level.value,
        )
        print(
            "Risk score:",
            result.risk_score,
        )
        print(
            "Files checked:",
            result.total_files_checked,
        )
        print(
            "Threats found:",
            result.total_threats_found,
        )

        if result.error_message:
            print(
                "Error:",
                result.error_message,
            )

        for threat in (
            result.archive_threats
        ):
            print(
                "[ARCHIVE]",
                threat.description,
            )

        for file_result in (
            result.file_results
        ):
            for threat in (
                file_result.threats
            ):
                print(
                    "[FILE]",
                    file_result
                    .file_path
                    .name,
                    "-",
                    threat.description,
                )


class DownloadsWatcher(
    FileWatcherInterface
):
    def __init__(
        self,
        scanner: ScannerServiceInterface,
        notifier: NotifierInterface,
        reporting_service: ReportingService,
        on_scan_completed: Callable[
            [ScanResult],
            None,
        ],
        downloads_dir: Path | None = None,
    ) -> None:
        self._scanner = scanner
        self._notifier = notifier
        self._reporting_service = (
            reporting_service
        )
        self._on_scan_completed = (
            on_scan_completed
        )

        self._downloads_dir = (
            downloads_dir
            or AppConfig.DOWNLOADS_DIR
        )

        self._observer = Observer()

        self._executor = (
            ThreadPoolExecutor(
                max_workers=2,
                thread_name_prefix=(
                    "file-scanner"
                ),
            )
        )

        self._logger = setup_logger()
        self._started = False

    def start(self) -> None:
        if self._started:
            return

        if (
            not self._downloads_dir
            .exists()
        ):
            raise FileNotFoundError(
                "Downloads folder does not exist: "
                f"{self._downloads_dir}"
            )

        if (
            not self._downloads_dir
            .is_dir()
        ):
            raise NotADirectoryError(
                "Downloads path is not a directory: "
                f"{self._downloads_dir}"
            )

        handler = (
            DownloadsEventHandler(
                scanner=self._scanner,
                notifier=self._notifier,
                reporting_service=(
                    self._reporting_service
                ),
                executor=self._executor,
                on_scan_completed=(
                    self._on_scan_completed
                ),
            )
        )

        self._observer.schedule(
            event_handler=handler,
            path=str(
                self._downloads_dir
            ),
            recursive=False,
        )

        self._observer.start()
        self._started = True

        self._logger.info(
            "Watching downloads folder: %s",
            self._downloads_dir,
        )

        print(
            "Watching downloads folder:",
            self._downloads_dir,
        )

    def stop(self) -> None:
        if not self._started:
            return

        self._observer.stop()
        self._observer.join()

        self._executor.shutdown(
            wait=True,
            cancel_futures=False,
        )

        self._started = False

        self._logger.info(
            "Downloads watcher stopped"
        )

        print(
            "Downloads watcher stopped"
        )