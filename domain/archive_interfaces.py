from abc import ABC, abstractmethod
from pathlib import Path

from domain.models import DetectedThreat


class ArchiveReaderInterface(ABC):
    @abstractmethod
    def supports(self, archive_path: Path) -> bool:
        """Проверяет, поддерживает ли reader указанный формат."""

    @abstractmethod
    def inspect(self, archive_path: Path) -> list[DetectedThreat]:
        """Проверяет структуру архива без запуска его содержимого."""

    @abstractmethod
    def extract(
        self,
        archive_path: Path,
        destination_dir: Path,
    ) -> list[Path]:
        """Безопасно извлекает файлы во временную папку."""