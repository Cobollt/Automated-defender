from pathlib import Path

from application.quarantine_manager import QuarantineManager
from domain.models import (
    QuarantineResult,
    SystemSecurityResult,
)


class SuccessfulSystemProvider:
    def __init__(self) -> None:
        self.called_with: Path | None = None

    def report_and_quarantine(
        self,
        file_path: Path,
    ) -> SystemSecurityResult:
        self.called_with = file_path
        file_path.unlink()

        return SystemSecurityResult(
            success=True,
            provider_name="Test System Security",
            file_path=file_path,
            threat_detected=True,
            file_isolated=True,
            message="Файл изолирован системной защитой.",
        )


class SuccessfulSystemProviderWithoutIsolation:
    def __init__(self) -> None:
        self.called_with: Path | None = None

    def report_and_quarantine(
        self,
        file_path: Path,
    ) -> SystemSecurityResult:
        self.called_with = file_path

        return SystemSecurityResult(
            success=True,
            provider_name="Test System Security",
            file_path=file_path,
            threat_detected=True,
            file_isolated=False,
            message=(
                "Системная защита обнаружила угрозу, "
                "но не подтвердила изоляцию."
            ),
        )


class FailedSystemProvider:
    def __init__(self) -> None:
        self.called_with: Path | None = None

    def report_and_quarantine(
        self,
        file_path: Path,
    ) -> SystemSecurityResult:
        self.called_with = file_path

        return SystemSecurityResult(
            success=False,
            provider_name="Test System Security",
            file_path=file_path,
            threat_detected=False,
            file_isolated=False,
            message="Системная защита не выполнила операцию.",
        )


class SystemProviderRemovesFileWithoutFlag:
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
            file_isolated=False,
            message=(
                "Файл был обработан, "
                "но провайдер не установил флаг изоляции."
            ),
        )


class FakeLocalProvider:
    def __init__(
        self,
        success: bool = True,
    ) -> None:
        self.success = success
        self.called = False
        self.called_with: Path | None = None

    def quarantine(
        self,
        file_path: Path,
    ) -> QuarantineResult:
        self.called = True
        self.called_with = file_path

        if not self.success:
            return QuarantineResult(
                success=False,
                provider_name="Fake Local Quarantine",
                original_path=file_path,
                quarantine_path=None,
                message="Локальный карантин завершился ошибкой.",
            )

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
            message="Файл перемещён в локальный карантин.",
        )


def test_local_provider_is_not_used_when_system_isolates(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "danger.exe"
    file_path.write_bytes(b"test")

    system_provider = SuccessfulSystemProvider()
    local_provider = FakeLocalProvider()

    manager = QuarantineManager(
        system_provider=system_provider,
        local_provider=local_provider,
    )

    result = manager.quarantine(file_path)

    assert result.success is True
    assert (
        result.provider_name
        == "Test System Security"
    )

    assert system_provider.called_with == file_path
    assert local_provider.called is False

    assert not file_path.exists()
    assert result.quarantine_path is None


def test_local_fallback_is_used_when_system_fails(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "danger.exe"
    file_path.write_bytes(b"test")

    system_provider = FailedSystemProvider()
    local_provider = FakeLocalProvider()

    manager = QuarantineManager(
        system_provider=system_provider,
        local_provider=local_provider,
    )

    result = manager.quarantine(file_path)

    assert result.success is True
    assert local_provider.called is True
    assert local_provider.called_with == file_path

    assert not file_path.exists()
    assert result.quarantine_path is not None
    assert result.quarantine_path.exists()

    assert (
        result.provider_name
        == "Fake Local Quarantine"
    )

    assert "Системная защита" in (
        result.message or ""
    )

    assert "локальный карантин" in (
        result.message or ""
    )


def test_local_fallback_is_used_when_system_does_not_isolate(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "danger.exe"
    file_path.write_bytes(b"test")

    system_provider = (
        SuccessfulSystemProviderWithoutIsolation()
    )

    local_provider = FakeLocalProvider()

    manager = QuarantineManager(
        system_provider=system_provider,
        local_provider=local_provider,
    )

    result = manager.quarantine(file_path)

    assert result.success is True
    assert local_provider.called is True
    assert not file_path.exists()

    assert result.quarantine_path is not None
    assert result.quarantine_path.exists()


def test_missing_file_returns_failure(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "missing.exe"

    local_provider = FakeLocalProvider()

    manager = QuarantineManager(
        system_provider=FailedSystemProvider(),
        local_provider=local_provider,
    )

    result = manager.quarantine(file_path)

    assert result.success is False
    assert result.quarantine_path is None
    assert local_provider.called is False
    assert "не существует" in (
        result.message or ""
    ).lower()


def test_missing_file_after_system_call_is_treated_as_success(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "danger.exe"
    file_path.write_bytes(b"test")

    local_provider = FakeLocalProvider()

    manager = QuarantineManager(
        system_provider=(
            SystemProviderRemovesFileWithoutFlag()
        ),
        local_provider=local_provider,
    )

    result = manager.quarantine(file_path)

    assert result.success is True
    assert local_provider.called is False
    assert not file_path.exists()

    assert (
        result.provider_name
        == "Test System Security"
    )

    assert "исчез" in (
        result.message or ""
    ).lower()


def test_failure_is_returned_when_local_fallback_fails(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "danger.exe"
    file_path.write_bytes(b"test")

    local_provider = FakeLocalProvider(
        success=False
    )

    manager = QuarantineManager(
        system_provider=FailedSystemProvider(),
        local_provider=local_provider,
    )

    result = manager.quarantine(file_path)

    assert result.success is False
    assert local_provider.called is True
    assert file_path.exists()
    assert result.quarantine_path is None


def test_original_file_is_not_modified_before_local_fallback(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "danger.exe"
    original_content = b"important test content"

    file_path.write_bytes(
        original_content
    )

    local_provider = FakeLocalProvider()

    manager = QuarantineManager(
        system_provider=FailedSystemProvider(),
        local_provider=local_provider,
    )

    result = manager.quarantine(file_path)

    assert result.success is True
    assert result.quarantine_path is not None

    assert result.quarantine_path.read_bytes() == (
        original_content
    )