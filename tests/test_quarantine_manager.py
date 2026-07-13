from pathlib import Path

from application.quarantine_manager import (
    QuarantineManager,
)
from domain.models import (
    QuarantineResult,
    SystemSecurityResult,
)


class SuccessfulSystemProvider:
    def report_and_quarantine(
        self,
        file_path: Path,
    ) -> SystemSecurityResult:
        file_path.unlink()

        return SystemSecurityResult(
            success=True,
            provider_name="Test System Security",
            file_path=file_path,
            threat_detected=True,
            file_isolated=True,
            message="File isolated by system.",
        )


class FailedSystemProvider:
    def report_and_quarantine(
        self,
        file_path: Path,
    ) -> SystemSecurityResult:
        return SystemSecurityResult(
            success=False,
            provider_name="Test System Security",
            file_path=file_path,
            threat_detected=False,
            file_isolated=False,
            message="System protection failed.",
        )


class FakeLocalProvider:
    def __init__(self) -> None:
        self.called = False

    def quarantine(
        self,
        file_path: Path,
    ) -> QuarantineResult:
        self.called = True

        destination = (
            file_path.parent
            / "local.quarantine"
        )

        file_path.rename(destination)

        return QuarantineResult(
            success=True,
            provider_name="Fake Local Quarantine",
            original_path=file_path,
            quarantine_path=destination,
            message="Moved locally.",
        )


def test_local_provider_is_not_used_when_system_isolates(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "danger.exe"
    file_path.write_bytes(b"test")

    local_provider = FakeLocalProvider()

    manager = QuarantineManager(
        system_provider=SuccessfulSystemProvider(),
        local_provider=local_provider,
    )

    result = manager.quarantine(file_path)

    assert result.success
    assert result.provider_name == "Test System Security"
    assert local_provider.called is False
    assert not file_path.exists()


def test_local_fallback_is_used_when_system_fails(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "danger.exe"
    file_path.write_bytes(b"test")

    local_provider = FakeLocalProvider()

    manager = QuarantineManager(
        system_provider=FailedSystemProvider(),
        local_provider=local_provider,
    )

    result = manager.quarantine(file_path)

    assert result.success
    assert local_provider.called is True
    assert not file_path.exists()
    assert result.quarantine_path is not None
    assert result.quarantine_path.exists()