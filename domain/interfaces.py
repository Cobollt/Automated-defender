from abc import ABC, abstractmethod
from pathlib import Path

from domain.enums import FileAction
from domain.models import (
    ActionResult,
    FileScanResult,
    QuarantineResult,
    ScanResult,
    SystemSecurityResult,
)


class FileAnalyzerInterface(ABC):
    @abstractmethod
    def analyze(self, file_path: Path) -> FileScanResult:
        pass


class ScannerServiceInterface(ABC):
    @abstractmethod
    def scan(self, target_path: Path) -> ScanResult:
        pass


class QuarantineProviderInterface(ABC):
    @abstractmethod
    def quarantine(
        self,
        file_path: Path,
    ) -> QuarantineResult:
        pass


class FileWatcherInterface(ABC):
    @abstractmethod
    def start(self) -> None:
        pass

    @abstractmethod
    def stop(self) -> None:
        pass


class NotifierInterface(ABC):
    @abstractmethod
    def notify(
        self,
        title: str,
        message: str,
    ) -> bool:
        pass

    @abstractmethod
    def notify_scan_result(
        self,
        result: ScanResult,
    ) -> bool:
        pass


class ActionServiceInterface(ABC):
    @abstractmethod
    def execute(
        self,
        action: FileAction,
        file_path: Path,
    ) -> ActionResult:
        pass


class SystemSecurityProviderInterface(ABC):
    @abstractmethod
    def report_and_quarantine(
        self,
        file_path: Path,
    ) -> SystemSecurityResult:
        """
        Передаёт файл системной защите.

        success=True означает, что запрос выполнен.
        file_isolated=True означает, что файл действительно
        удалён или помещён в системный карантин.
        """
        pass


class AutostartServiceInterface(ABC):
    @abstractmethod
    def enable(self) -> bool:
        """Включает автоматический запуск приложения."""
        pass

    @abstractmethod
    def disable(self) -> bool:
        """Отключает автоматический запуск приложения."""
        pass

    @abstractmethod
    def is_enabled(self) -> bool:
        """Проверяет, включён ли автоматический запуск."""
        pass