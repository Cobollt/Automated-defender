import stat
import zipfile
from pathlib import Path

from config import AppConfig
from domain.archive_interfaces import (
    ArchiveReaderInterface,
)
from domain.enums import ThreatType
from domain.models import DetectedThreat
from infrastructure.archive_readers.base_reader import (
    BaseArchiveReader,
)


class ZipArchiveReader(
    BaseArchiveReader,
    ArchiveReaderInterface,
):
    MAGIC_SIGNATURES = (
        b"PK\x03\x04",
        b"PK\x05\x06",
        b"PK\x07\x08",
    )

    def supports(
        self,
        archive_path: Path,
    ) -> bool:
        try:
            with archive_path.open(
                "rb"
            ) as file:
                header = file.read(4)

        except OSError:
            return False

        return (
            archive_path
            .suffix
            .lower()
            == ".zip"
            or header.startswith(
                self.MAGIC_SIGNATURES
            )
        )

    def inspect(
        self,
        archive_path: Path,
    ) -> list[DetectedThreat]:
        if not zipfile.is_zipfile(
            archive_path
        ):
            return [
                DetectedThreat(
                    threat_type=(
                        ThreatType
                        .UNKNOWN_FORMAT
                    ),
                    description=(
                        "File has a ZIP-like "
                        "extension but is not "
                        "a valid ZIP archive"
                    ),
                    score=20,
                    file_path=archive_path,
                )
            ]

        threats: list[
            DetectedThreat
        ] = []

        try:
            with zipfile.ZipFile(
                archive_path,
                "r",
            ) as archive:
                members = (
                    archive.infolist()
                )

                threats.extend(
                    self._inspect_limits(
                        archive_path,
                        members,
                    )
                )

                for member in members:
                    (
                        _,
                        path_threat,
                    ) = (
                        self
                        .validate_member_path(
                            archive_path=(
                                archive_path
                            ),
                            destination_dir=(
                                Path(
                                    "/safe-inspection-root"
                                )
                            ),
                            member_name=(
                                member.filename
                            ),
                        )
                    )

                    if (
                        path_threat
                        is not None
                    ):
                        threats.append(
                            path_threat
                        )

                    if self._is_symlink(
                        member
                    ):
                        threats.append(
                            DetectedThreat(
                                threat_type=(
                                    ThreatType
                                    .UNSAFE_PATH
                                ),
                                description=(
                                    "Archive contains "
                                    "symbolic link: "
                                    f"{member.filename}"
                                ),
                                score=40,
                                file_path=(
                                    archive_path
                                ),
                            )
                        )

                    if (
                        member.flag_bits
                        & 0x1
                    ):
                        threats.append(
                            DetectedThreat(
                                threat_type=(
                                    ThreatType
                                    .ENCRYPTED_ARCHIVE
                                ),
                                description=(
                                    "Encrypted archive "
                                    "entry: "
                                    f"{member.filename}"
                                ),
                                score=25,
                                file_path=(
                                    archive_path
                                ),
                            )
                        )

        except (
            OSError,
            zipfile.BadZipFile,
            RuntimeError,
        ) as error:
            return [
                DetectedThreat(
                    threat_type=(
                        ThreatType
                        .UNKNOWN_FORMAT
                    ),
                    description=(
                        "Unable to inspect "
                        "ZIP archive: "
                        f"{error}"
                    ),
                    score=20,
                    file_path=archive_path,
                )
            ]

        return threats

    def extract(
        self,
        archive_path: Path,
        destination_dir: Path,
    ) -> list[Path]:
        extracted_files: list[
            Path
        ] = []

        extracted_size = 0
        extracted_count = 0

        with zipfile.ZipFile(
            archive_path,
            "r",
        ) as archive:
            members = (
                archive.infolist()
            )

            self._raise_if_limits_exceeded(
                archive_path,
                members,
            )

            for member in members:
                if (
                    member.is_dir()
                    or self._is_symlink(
                        member
                    )
                ):
                    continue

                (
                    target_path,
                    threat,
                ) = (
                    self
                    .validate_member_path(
                        archive_path=(
                            archive_path
                        ),
                        destination_dir=(
                            destination_dir
                        ),
                        member_name=(
                            member.filename
                        ),
                    )
                )

                if (
                    threat is not None
                    or target_path is None
                ):
                    continue

                if (
                    member.flag_bits
                    & 0x1
                ):
                    raise ValueError(
                        "Encrypted ZIP entry "
                        "is not supported: "
                        f"{member.filename}"
                    )

                extracted_count += 1

                if (
                    extracted_count
                    > AppConfig
                    .MAX_FILES_IN_ARCHIVE
                ):
                    raise ValueError(
                        "Archive file count "
                        "exceeded during "
                        "extraction"
                    )

                target_path.parent.mkdir(
                    parents=True,
                    exist_ok=True,
                )

                temporary_path = (
                    target_path.with_name(
                        "."
                        f"{target_path.name}"
                        ".extracting"
                    )
                )

                try:
                    with archive.open(
                        member,
                        "r",
                    ) as source:
                        with (
                            temporary_path
                            .open("wb")
                        ) as target:
                            written = (
                                self.copy_limited(
                                    source=source,
                                    target=target,
                                    current_size=(
                                        extracted_size
                                    ),
                                )
                            )

                    temporary_path.replace(
                        target_path
                    )

                except Exception:
                    temporary_path.unlink(
                        missing_ok=True
                    )

                    raise

                extracted_size += (
                    written
                )

                extracted_files.append(
                    target_path
                )

        return extracted_files

    def _inspect_limits(
        self,
        archive_path: Path,
        members: list[
            zipfile.ZipInfo
        ],
    ) -> list[DetectedThreat]:
        threats: list[
            DetectedThreat
        ] = []

        file_members = [
            member
            for member in members
            if not member.is_dir()
        ]

        if (
            len(file_members)
            > AppConfig
            .MAX_FILES_IN_ARCHIVE
        ):
            threats.append(
                self.archive_bomb_threat(
                    archive_path,
                    (
                        "Archive contains "
                        "too many entries: "
                        f"{len(file_members)}"
                    ),
                    score=40,
                )
            )

        total_size = sum(
            member.file_size
            for member in file_members
        )

        if (
            total_size
            > self.max_extracted_size()
        ):
            threats.append(
                self.archive_bomb_threat(
                    archive_path,
                    (
                        "Declared extracted "
                        "size exceeds limit: "
                        f"{total_size} bytes"
                    ),
                )
            )

        compressed_size = sum(
            member.compress_size
            for member in file_members
        )

        if (
            compressed_size > 0
            and total_size > 0
        ):
            compression_ratio = (
                total_size
                / compressed_size
            )

            if (
                compression_ratio
                > AppConfig
                .MAX_COMPRESSION_RATIO
            ):
                threats.append(
                    self.archive_bomb_threat(
                        archive_path,
                        (
                            "Suspicious "
                            "compression ratio: "
                            f"{compression_ratio:.2f}"
                        ),
                        score=40,
                    )
                )

        for member in file_members:
            if (
                member.compress_size <= 0
                or member.file_size <= 0
            ):
                continue

            member_ratio = (
                member.file_size
                / member.compress_size
            )

            if (
                member_ratio
                > AppConfig
                .MAX_COMPRESSION_RATIO
            ):
                threats.append(
                    self.archive_bomb_threat(
                        archive_path,
                        (
                            "Suspicious entry "
                            "compression ratio: "
                            f"{member.filename} "
                            f"({member_ratio:.2f})"
                        ),
                        score=40,
                    )
                )

        return threats

    def _raise_if_limits_exceeded(
        self,
        archive_path: Path,
        members: list[
            zipfile.ZipInfo
        ],
    ) -> None:
        threats = self._inspect_limits(
            archive_path,
            members,
        )

        bomb_threat = next(
            (
                threat
                for threat in threats
                if (
                    threat.threat_type
                    == ThreatType
                    .ARCHIVE_BOMB_RISK
                )
            ),
            None,
        )

        if bomb_threat is not None:
            raise ValueError(
                bomb_threat.description
            )

    @staticmethod
    def _is_symlink(
        member: zipfile.ZipInfo,
    ) -> bool:
        unix_mode = (
            member.external_attr
            >> 16
        ) & 0xFFFF

        return stat.S_ISLNK(
            unix_mode
        )