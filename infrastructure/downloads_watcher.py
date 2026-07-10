import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from config import AppConfig
from application.scanner_service import ScannerService

class DownloadsEventHandler(FileSystemEventHandler):
    def __init__(self, scanner: ScannerService) -> None:
        self.scanner = scanner

    def on_created(self, event) -> None:
        if event.is_directory:
            return

        file_path = Path(event.src_path)
        self._handle_file(file_path)

    def _handle_file(self, file_path: Path) -> None:
        if not self._wait_until_file_ready(file_path):
            print(f"[SKIP] File is not ready: {file_path}")
            return

        result = self.scanner.scan(file_path)

        print()
        print("[SCAN COMPLETED]")
        print("File:", result.target_path)
        print("Status:", result.status.value)
        print("Risk level:", result.risk_level.value)
        print("Risk score:", result.risk_score)
        print("Files checked:", result.total_files_checked)
        print("Threats found:", result.total_threats_found)

    def _wait_until_file_ready(self, file_path: Path) -> bool:
        last_size = -1

        for _ in range(AppConfig.FILE_READY_TIMEOUT):
            if not file_path.exists():
                return False

            current_size = file_path.stat().st_size

            if current_size == last_size:
                return True

            last_size = current_size
            time.sleep(AppConfig.FILE_READY_CHECK_INTERVAL)

        return False


class DownloadsWatcher:
    def __init__(self, scanner: ScannerService) -> None:
        self.scanner = scanner
        self.observer = Observer()

    def start(self) -> None:
        handler = DownloadsEventHandler(self.scanner)

        self.observer.schedule(
            handler,
            str(AppConfig.DOWNLOADS_DIR),
            recursive=False
        )

        self.observer.start()

        print(f"Watching downloads folder: {AppConfig.DOWNLOADS_DIR}")

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self) -> None:
        self.observer.stop()
        self.observer.join()
        print("Downloads watcher stopped")