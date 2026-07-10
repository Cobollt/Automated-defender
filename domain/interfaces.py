from abc import ABC, abstractmethod
from pathlib import Path

from domain.models import FileScanResult, ScanResult, QuarantineResult


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
    def quarantine(self, file_path: Path) -> QuarantineResult:
        pass