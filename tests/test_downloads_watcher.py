from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from infrastructure.downloads_watcher import (
    DownloadsEventHandler,
)


class FakeScanner:
    def scan(self, file_path: Path):
        raise AssertionError(
            "Scanner should not be called in this test"
        )


class FakeNotifier:
    def notify(self, title: str, message: str) -> bool:
        return True

    def notify_scan_result(self, result) -> bool:
        return True


class FakeReportingService:
    def save_scan_result(self, result):
        return None


def create_handler(
    executor: ThreadPoolExecutor,
) -> DownloadsEventHandler:
    return DownloadsEventHandler(
        scanner=FakeScanner(),
        notifier=FakeNotifier(),
        reporting_service=FakeReportingService(),
        executor=executor,
        on_scan_completed=lambda result: None,
    )


def test_temporary_download_is_ignored(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "file.crdownload"
    file_path.write_text(
        "partial",
        encoding="utf-8",
    )

    with ThreadPoolExecutor(max_workers=1) as executor:
        handler = create_handler(executor)

        assert handler._should_ignore(file_path) is True


def test_hidden_file_is_ignored(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / ".hidden"
    file_path.write_text(
        "hidden",
        encoding="utf-8",
    )

    with ThreadPoolExecutor(max_workers=1) as executor:
        handler = create_handler(executor)

        assert handler._should_ignore(file_path) is True


def test_regular_file_is_not_ignored(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "archive.zip"
    file_path.write_bytes(b"test")

    with ThreadPoolExecutor(max_workers=1) as executor:
        handler = create_handler(executor)

        assert handler._should_ignore(file_path) is False