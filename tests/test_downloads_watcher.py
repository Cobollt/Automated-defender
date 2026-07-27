import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from config import AppConfig
from domain.enums import (
    RiskLevel,
    ScanStatus,
)
from domain.models import ScanResult
from infrastructure.downloads_watcher import (
    DownloadsEventHandler,
)


class FakeScanner:
    def __init__(
        self,
        risk_level: RiskLevel = RiskLevel.SAFE,
        risk_score: int = 0,
        error: Exception | None = None,
    ) -> None:
        self.risk_level = risk_level
        self.risk_score = risk_score
        self.error = error

        self.scanned_files: list[
            Path
        ] = []

    def scan(
        self,
        file_path: Path,
    ) -> ScanResult:
        self.scanned_files.append(
            file_path
        )

        if self.error is not None:
            raise self.error

        return ScanResult(
            target_path=file_path,
            target_sha256=(
                "test-sha256"
            ),
            status=(
                ScanStatus.COMPLETED
            ),
            risk_score=(
                self.risk_score
            ),
            risk_level=(
                self.risk_level
            ),
            total_files_checked=1,
            total_threats_found=0,
        )


class FakeNotifier:
    def __init__(self) -> None:
        self.results: list[
            ScanResult
        ] = []

    def notify(
        self,
        title: str,
        message: str,
    ) -> bool:
        return True

    def notify_scan_result(
        self,
        result: ScanResult,
    ) -> bool:
        self.results.append(
            result
        )

        return True


class FakeReportingService:
    def __init__(self) -> None:
        self.results: list[
            ScanResult
        ] = []

    def save_scan_result(
        self,
        result: ScanResult,
    ) -> Path:
        self.results.append(
            result
        )

        return Path(
            "report.json"
        )


def configure_fast_file_ready_check(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        AppConfig,
        "FILE_READY_TIMEOUT",
        1,
    )

    monkeypatch.setattr(
        AppConfig,
        "FILE_READY_CHECK_INTERVAL",
        0.01,
    )

    monkeypatch.setattr(
        AppConfig,
        "FILE_STABLE_CHECKS_REQUIRED",
        1,
    )


def create_handler(
    executor: ThreadPoolExecutor,
    scanner: FakeScanner | None = None,
    notifier: FakeNotifier | None = None,
    reporting_service: (
        FakeReportingService | None
    ) = None,
    completed_results: (
        list[ScanResult] | None
    ) = None,
) -> DownloadsEventHandler:
    scanner = (
        scanner
        or FakeScanner()
    )

    notifier = (
        notifier
        or FakeNotifier()
    )

    reporting_service = (
        reporting_service
        or FakeReportingService()
    )

    completed_results = (
        completed_results
        if completed_results
        is not None
        else []
    )

    return DownloadsEventHandler(
        scanner=scanner,
        notifier=notifier,
        reporting_service=(
            reporting_service
        ),
        executor=executor,
        on_scan_completed=(
            completed_results.append
        ),
    )


@pytest.mark.parametrize(
    "risk_level,risk_score",
    [
        (
            RiskLevel.SAFE,
            0,
        ),
        (
            RiskLevel.LOW,
            20,
        ),
        (
            RiskLevel.MEDIUM,
            50,
        ),
    ],
)
def test_non_dangerous_result_is_saved_without_notification(
    tmp_path: Path,
    monkeypatch,
    risk_level: RiskLevel,
    risk_score: int,
) -> None:
    configure_fast_file_ready_check(
        monkeypatch
    )

    file_path = (
        tmp_path / "safe.txt"
    )

    file_path.write_text(
        "safe",
        encoding="utf-8",
    )

    scanner = FakeScanner(
        risk_level=risk_level,
        risk_score=risk_score,
    )

    notifier = FakeNotifier()

    reporting_service = (
        FakeReportingService()
    )

    completed_results: list[
        ScanResult
    ] = []

    with ThreadPoolExecutor(
        max_workers=1
    ) as executor:
        handler = create_handler(
            executor=executor,
            scanner=scanner,
            notifier=notifier,
            reporting_service=(
                reporting_service
            ),
            completed_results=(
                completed_results
            ),
        )

        handler._process_file(
            file_path.resolve()
        )

    assert (
        scanner.scanned_files
        == [
            file_path.resolve()
        ]
    )

    assert (
        len(
            reporting_service
            .results
        )
        == 1
    )

    assert notifier.results == []

    assert (
        completed_results
        == []
    )


@pytest.mark.parametrize(
    "risk_level,risk_score",
    [
        (
            RiskLevel.HIGH,
            70,
        ),
        (
            RiskLevel.CRITICAL,
            100,
        ),
    ],
)
def test_dangerous_result_sends_notification_and_callback(
    tmp_path: Path,
    monkeypatch,
    risk_level: RiskLevel,
    risk_score: int,
) -> None:
    configure_fast_file_ready_check(
        monkeypatch
    )

    file_path = (
        tmp_path
        / "danger.exe"
    )

    file_path.write_bytes(
        b"MZ test"
    )

    scanner = FakeScanner(
        risk_level=risk_level,
        risk_score=risk_score,
    )

    notifier = FakeNotifier()

    reporting_service = (
        FakeReportingService()
    )

    completed_results: list[
        ScanResult
    ] = []

    with ThreadPoolExecutor(
        max_workers=1
    ) as executor:
        handler = create_handler(
            executor=executor,
            scanner=scanner,
            notifier=notifier,
            reporting_service=(
                reporting_service
            ),
            completed_results=(
                completed_results
            ),
        )

        handler._process_file(
            file_path.resolve()
        )

    assert (
        len(
            reporting_service
            .results
        )
        == 1
    )

    assert (
        len(
            notifier.results
        )
        == 1
    )

    assert (
        len(
            completed_results
        )
        == 1
    )

    assert (
        completed_results[0]
        .risk_level
        == risk_level
    )

    assert (
        completed_results[0]
        .risk_score
        == risk_score
    )


def test_temporary_download_is_ignored(
    tmp_path: Path,
) -> None:
    file_path = (
        tmp_path
        / "file.crdownload"
    )

    file_path.write_text(
        "partial",
        encoding="utf-8",
    )

    with ThreadPoolExecutor(
        max_workers=1
    ) as executor:
        handler = create_handler(
            executor
        )

        assert (
            handler._should_ignore(
                file_path
            )
            is True
        )


def test_partial_download_is_ignored(
    tmp_path: Path,
) -> None:
    file_path = (
        tmp_path
        / "archive.part"
    )

    file_path.write_text(
        "partial",
        encoding="utf-8",
    )

    with ThreadPoolExecutor(
        max_workers=1
    ) as executor:
        handler = create_handler(
            executor
        )

        assert (
            handler._should_ignore(
                file_path
            )
            is True
        )


def test_download_extension_is_ignored(
    tmp_path: Path,
) -> None:
    file_path = (
        tmp_path
        / "archive.download"
    )

    file_path.write_text(
        "partial",
        encoding="utf-8",
    )

    with ThreadPoolExecutor(
        max_workers=1
    ) as executor:
        handler = create_handler(
            executor
        )

        assert (
            handler._should_ignore(
                file_path
            )
            is True
        )


def test_hidden_file_is_ignored(
    tmp_path: Path,
) -> None:
    file_path = (
        tmp_path
        / ".hidden"
    )

    file_path.write_text(
        "hidden",
        encoding="utf-8",
    )

    with ThreadPoolExecutor(
        max_workers=1
    ) as executor:
        handler = create_handler(
            executor
        )

        assert (
            handler._should_ignore(
                file_path
            )
            is True
        )


def test_regular_file_is_not_ignored(
    tmp_path: Path,
) -> None:
    file_path = (
        tmp_path
        / "archive.zip"
    )

    file_path.write_bytes(
        b"test"
    )

    with ThreadPoolExecutor(
        max_workers=1
    ) as executor:
        handler = create_handler(
            executor
        )

        assert (
            handler._should_ignore(
                file_path
            )
            is False
        )


def test_missing_file_is_not_ready(
    tmp_path: Path,
    monkeypatch,
) -> None:
    configure_fast_file_ready_check(
        monkeypatch
    )

    missing_file = (
        tmp_path
        / "missing.zip"
    )

    with ThreadPoolExecutor(
        max_workers=1
    ) as executor:
        handler = create_handler(
            executor
        )

        assert (
            handler
            ._wait_until_file_ready(
                missing_file
            )
            is False
        )


def test_stable_file_becomes_ready(
    tmp_path: Path,
    monkeypatch,
) -> None:
    configure_fast_file_ready_check(
        monkeypatch
    )

    monkeypatch.setattr(
        AppConfig,
        "FILE_STABLE_CHECKS_REQUIRED",
        2,
    )

    file_path = (
        tmp_path
        / "stable.zip"
    )

    file_path.write_bytes(
        b"stable"
    )

    with ThreadPoolExecutor(
        max_workers=1
    ) as executor:
        handler = create_handler(
            executor
        )

        assert (
            handler
            ._wait_until_file_ready(
                file_path
            )
            is True
        )


def test_same_file_is_not_scheduled_twice(
    tmp_path: Path,
) -> None:
    file_path = (
        tmp_path
        / "file.zip"
    ).resolve()

    file_path.write_bytes(
        b"content"
    )

    scanner = FakeScanner()

    with ThreadPoolExecutor(
        max_workers=1
    ) as executor:
        handler = create_handler(
            executor=executor,
            scanner=scanner,
        )

        with (
            handler
            ._processing_lock
        ):
            handler._processing_files.add(
                file_path
            )

        handler._schedule_file(
            file_path
        )

        time.sleep(
            0.05
        )

    assert (
        scanner.scanned_files
        == []
    )


def test_processing_file_is_removed_after_scan(
    tmp_path: Path,
    monkeypatch,
) -> None:
    configure_fast_file_ready_check(
        monkeypatch
    )

    file_path = (
        tmp_path
        / "file.txt"
    ).resolve()

    file_path.write_text(
        "content",
        encoding="utf-8",
    )

    with ThreadPoolExecutor(
        max_workers=1
    ) as executor:
        handler = create_handler(
            executor
        )

        assert (
            handler
            ._try_mark_as_processing(
                file_path
            )
            is True
        )

        handler._process_file(
            file_path
        )

        assert (
            file_path
            not in handler
            ._processing_files
        )


def test_processing_file_is_removed_after_scanner_error(
    tmp_path: Path,
    monkeypatch,
) -> None:
    configure_fast_file_ready_check(
        monkeypatch
    )

    file_path = (
        tmp_path
        / "broken.zip"
    ).resolve()

    file_path.write_bytes(
        b"broken"
    )

    scanner = FakeScanner(
        error=RuntimeError(
            "scanner failed"
        )
    )

    with ThreadPoolExecutor(
        max_workers=1
    ) as executor:
        handler = create_handler(
            executor=executor,
            scanner=scanner,
        )

        assert (
            handler
            ._try_mark_as_processing(
                file_path
            )
            is True
        )

        handler._process_file(
            file_path
        )

        assert (
            file_path
            not in handler
            ._processing_files
        )


def test_try_mark_as_processing_is_atomic(
    tmp_path: Path,
) -> None:
    file_path = (
        tmp_path
        / "atomic.zip"
    ).resolve()

    file_path.write_bytes(
        b"content"
    )

    with ThreadPoolExecutor(
        max_workers=1
    ) as executor:
        handler = create_handler(
            executor
        )

        assert (
            handler
            ._try_mark_as_processing(
                file_path
            )
            is True
        )

        assert (
            handler
            ._try_mark_as_processing(
                file_path
            )
            is False
        )

        handler._release_processing_file(
            file_path
        )

        assert (
            handler
            ._try_mark_as_processing(
                file_path
            )
            is True
        )

        handler._release_processing_file(
            file_path
        )