from pathlib import Path

from domain.archive_interfaces import (
    ArchiveReaderInterface,
)
from domain.enums import ThreatType
from domain.models import DetectedThreat
from utils.file_type import FileTypeDetector


class ArchiveDetector:
    SIGNATURE_SAMPLE_SIZE = 512

    KNOWN_ARCHIVE_EXTENSIONS = {
        ".zip",
        ".tar",
        ".tgz",
        ".gz",
        ".gzip",
        ".bz2",
        ".xz",
        ".rar",
        ".7z",
        ".custom",
    }

    def __init__(
        self,
        readers: list[
            ArchiveReaderInterface
        ],
    ) -> None:
        self._readers = list(
            readers
        )

    def is_archive(
        self,
        file_path: Path,
    ) -> bool:
        """
        Возвращает True только если для
        архива существует reader.

        Метод сохранён для совместимости
        с существующим кодом.
        """
        return (
            self.get_reader(
                file_path
            )
            is not None
        )

    def is_archive_candidate(
        self,
        file_path: Path,
    ) -> bool:
        """
        Возвращает True для любого файла,
        похожего на архив:

        - есть поддерживаемый reader;
        - известная архивная сигнатура;
        - известное архивное расширение.
        """
        file_path = Path(
            file_path
        )

        if (
            self.get_reader(
                file_path
            )
            is not None
        ):
            return True

        detected_type = (
            self.detect_file_type(
                file_path
            )
        )

        if (
            detected_type
            is not None
            and detected_type.is_archive
        ):
            return True

        return (
            file_path
            .suffix
            .lower()
            in self.KNOWN_ARCHIVE_EXTENSIONS
        )

    def get_reader(
        self,
        file_path: Path,
    ) -> ArchiveReaderInterface | None:
        file_path = Path(
            file_path
        )

        for reader in self._readers:
            try:
                if reader.supports(
                    file_path
                ):
                    return reader

            except (
                OSError,
                ValueError,
            ):
                continue

        return None

    def detect_file_type(
        self,
        file_path: Path,
    ):
        file_path = Path(
            file_path
        )

        if (
            not file_path.exists()
            or not file_path.is_file()
        ):
            return None

        try:
            with file_path.open(
                "rb"
            ) as file:
                sample = file.read(
                    self.SIGNATURE_SAMPLE_SIZE
                )

        except OSError:
            return None

        return (
            FileTypeDetector.detect(
                sample
            )
        )

    def get_unhandled_archive_threat(
        self,
        file_path: Path,
        relative_path: (
            str | None
        ) = None,
    ) -> DetectedThreat | None:
        """
        Возвращает угрозу, если файл похож
        на архив, но подходящего reader нет.

        Если reader существует, возвращает
        None — дальнейшей обработкой должен
        заниматься reader.
        """
        file_path = Path(
            file_path
        )

        if (
            self.get_reader(
                file_path
            )
            is not None
        ):
            return None

        detected_type = (
            self.detect_file_type(
                file_path
            )
        )

        if (
            detected_type
            is not None
            and detected_type.is_archive
        ):
            return DetectedThreat(
                threat_type=(
                    ThreatType
                    .UNSUPPORTED_ARCHIVE
                ),
                description=(
                    "Archive format was "
                    "detected but no safe "
                    "archive reader is "
                    "available: "
                    f"{detected_type.name}"
                ),
                score=25,
                file_path=file_path,
                relative_path=(
                    relative_path
                ),
            )

        extension = (
            file_path
            .suffix
            .lower()
        )

        if (
            extension
            in self.KNOWN_ARCHIVE_EXTENSIONS
        ):
            return DetectedThreat(
                threat_type=(
                    ThreatType
                    .UNKNOWN_FORMAT
                ),
                description=(
                    "File uses an archive "
                    "extension but its "
                    "format could not be "
                    "safely recognized: "
                    f"{extension}"
                ),
                score=20,
                file_path=file_path,
                relative_path=(
                    relative_path
                ),
            )

        return None