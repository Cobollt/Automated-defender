import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from config import AppConfig
from domain.enums import RiskLevel, ScanStatus
from domain.models import ScanResult
from infrastructure.downloads_watcher import DownloadsEventHandler


class FakeScanner:
    def __init__(self) -> None:
        self.scanned_files: list[Path] = []

    def scan(
        self,
        file_path: Path,
    ) -> ScanResult:
        self.scanned_files.append(file_path)

        return ScanResult(
            target_path=file_path,
            target_sha256="test-sha256",
            status=ScanStatus.COMPLETED,
            risk_score=0,
            risk_level=RiskLevel.SAFE,
            total_files_checked=1,
            total_threats_found=0,
        )


class FakeNotifier:
    def __init__(self) -> None:
        self.results: list[ScanResult] = []

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
        self.results.append(result)
        return True


class FakeReportingService:
    def __init__(self) -> None:
        self.results: list[ScanResult] = []

    def save_scan_result(
        self,
        result: ScanResult,
    ) -> Path:
        self.results.append(result)
        return Path("report.json")


class FakeScanner:
    def __init__(
        self,
        risk_level: RiskLevel = RiskLevel.SAFE,
        risk_score: int = 0,
    ) -> None:
        self.risk_level = risk_level
        self.risk_score = risk_score
        self.scanned_files: list[Path] = []

    def scan(
        self,
        file_path: Path,
    ) -> ScanResult:
        self.scanned_files.append(file_path)

        return ScanResult(
            target_path=file_path,
            target_sha256="test-sha256",
            status=ScanStatus.COMPLETED,
            risk_score=self.risk_score,
            risk_level=self.risk_level,
            total_files_checked=1,
            total_threats_found=0,
        )


def test_safe_result_is_ignored_automatically(
    tmp_path: Path,
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

    file_path = tmp_path / "safe.txt"
    file_path.write_text(
        "safe",
        encoding="utf-8",
    )

    scanner = FakeScanner(
        risk_level=RiskLevel.SAFE,
        risk_score=0,
    )
    notifier = FakeNotifier()
    reporting_service = FakeReportingService()
    completed_results: list[ScanResult] = []

    with ThreadPoolExecutor(max_workers=1) as executor:
        handler = create_handler(
            executor=executor,
            scanner=scanner,
            notifier=notifier,
            reporting_service=reporting_service,
            completed_results=completed_results,
        )

        handler._process_file(
            file_path.resolve()
        )

    assert scanner.scanned_files == [
        file_path.resolve()
    ]

    assert len(reporting_service.results) == 1
    assert notifier.results == []
    assert completed_results == []


def test_high_risk_result_sends_notification_and_opens_window(
    tmp_path: Path,
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

    file_path = tmp_path / "danger.exe"
    file_path.write_bytes(b"MZ test")

    scanner = FakeScanner(
        risk_level=RiskLevel.HIGH,
        risk_score=70,
    )
    notifier = FakeNotifier()
    reporting_service = FakeReportingService()
    completed_results: list[ScanResult] = []

    with ThreadPoolExecutor(max_workers=1) as executor:
        handler = create_handler(
            executor=executor,
            scanner=scanner,
            notifier=notifier,
            reporting_service=reporting_service,
            completed_results=completed_results,
        )

        handler._process_file(
            file_path.resolve()
        )

    assert len(reporting_service.results) == 1
    assert len(notifier.results) == 1
    assert len(completed_results) == 1

    assert (
        completed_results[0].risk_level
        == RiskLevel.HIGH
    )


def create_handler(
    executor: ThreadPoolExecutor,
    scanner: FakeScanner | None = None,
    notifier: FakeNotifier | None = None,
    reporting_service: FakeReportingService | None = None,
    completed_results: list[ScanResult] | None = None,
) -> DownloadsEventHandler:
    scanner = scanner or FakeScanner()
    notifier = notifier or FakeNotifier()
    reporting_service = (
        reporting_service
        or FakeReportingService()
    )
    completed_results = (
        completed_results
        if completed_results is not None
        else []
    )

    return DownloadsEventHandler(
        scanner=scanner,
        notifier=notifier,
        reporting_service=reporting_service,
        executor=executor,
        on_scan_completed=completed_results.append,
    )


def test_temporary_download_is_ignored(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "file.crdownload"
    file_path.write_text(
        "partial",
        encoding="utf-8",
    )

    with ThreadPoolExecutor(
        max_workers=1
    ) as executor:
        handler = create_handler(executor)

        assert handler._should_ignore(
            file_path
        ) is True


def test_partial_download_is_ignored(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "archive.part"
    file_path.write_text(
        "partial",
        encoding="utf-8",
    )

    with ThreadPoolExecutor(
        max_workers=1
    ) as executor:
        handler = create_handler(executor)

        assert handler._should_ignore(
            file_path
        ) is True


def test_hidden_file_is_ignored(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / ".hidden"
    file_path.write_text(
        "hidden",
        encoding="utf-8",
    )

    with ThreadPoolExecutor(
        max_workers=1
    ) as executor:
        handler = create_handler(executor)

        assert handler._should_ignore(
            file_path
        ) is True


def test_regular_file_is_not_ignored(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "archive.zip"
    file_path.write_bytes(b"test")

    with ThreadPoolExecutor(
        max_workers=1
    ) as executor:
        handler = create_handler(executor)

        assert handler._should_ignore(
            file_path
        ) is False


def test_missing_file_is_not_ready(
    tmp_path: Path,
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

    missing_file = tmp_path / "missing.zip"

    with ThreadPoolExecutor(
        max_workers=1
    ) as executor:
        handler = create_handler(executor)

        assert handler._wait_until_file_ready(
            missing_file
        ) is False


def test_stable_file_becomes_ready(
    tmp_path: Path,
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
        2,
    )

    file_path = tmp_path / "stable.zip"
    file_path.write_bytes(b"stable")

    with ThreadPoolExecutor(
        max_workers=1
    ) as executor:
        handler = create_handler(executor)

        assert handler._wait_until_file_ready(
            file_path
        ) is True


def test_process_file_runs_complete_pipeline(
    tmp_path: Path,
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

    file_path = tmp_path / "safe.txt"
    file_path.write_text(
        "safe",
        encoding="utf-8",
    )

    scanner = FakeScanner()
    notifier = FakeNotifier()
    reporting_service = FakeReportingService()
    completed_results: list[ScanResult] = []

    with ThreadPoolExecutor(
        max_workers=1
    ) as executor:
        handler = create_handler(
            executor=executor,
            scanner=scanner,
            notifier=notifier,
            reporting_service=reporting_service,
            completed_results=completed_results,
        )

        handler._process_file(file_path)

    assert scanner.scanned_files == [
        file_path.resolve()
    ]

    assert len(
        reporting_service.results
    ) == 1

    assert len(notifier.results) == 1
    assert len(completed_results) == 1

    scan_result = completed_results[0]

    assert scan_result.target_path == (
        file_path.resolve()
    )
    assert scan_result.target_sha256 == (
        "test-sha256"
    )
    assert scan_result.status == (
        ScanStatus.COMPLETED
    )


def test_same_file_is_not_scheduled_twice(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "file.zip"
    file_path.write_bytes(b"content")

    scanner = FakeScanner()

    with ThreadPoolExecutor(
        max_workers=1
    ) as executor:
        handler = create_handler(
            executor=executor,
            scanner=scanner,
        )

        handler._wait_until_file_ready = (
            lambda path: True
        )

        first_future = handler._executor.submit(
            time.sleep,
            0.05,
        )

        with handler._processing_lock:
            handler._processing_files.add(
                file_path.resolve()
            )

        handler._schedule_file(file_path)

        first_future.result()

    assert scanner.scanned_files == []


def test_processing_file_is_removed_after_scan(
    tmp_path: Path,
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

    file_path = tmp_path / "file.txt"
    file_path.write_text(
        "content",
        encoding="utf-8",
    )

    with ThreadPoolExecutor(
        max_workers=1
    ) as executor:
        handler = create_handler(executor)

        resolved_path = file_path.resolve()

        with handler._processing_lock:
            handler._processing_files.add(
                resolved_path
            )

        handler._process_file(
            resolved_path
        )

        assert resolved_path not in (
            handler._processing_files
        )