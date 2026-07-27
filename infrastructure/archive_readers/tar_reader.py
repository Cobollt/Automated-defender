import tarfile
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


class TarArchiveReader(
    BaseArchiveReader,
    ArchiveReaderInterface,
):
    EXTENSIONS = {
        ".tar",
        ".gz",
        ".tgz",
        ".bz2",
        ".xz",
    }

    def supports(
        self,
        archive_path: Path,
    ) -> bool:
        try:
            return tarfile.is_tarfile(
                archive_path
            )

        except OSError:
            return False

    def inspect(
        self,
        archive_path: Path,
    ) -> list[DetectedThreat]:
        if not self.supports(
            archive_path
        ):
            return [
                DetectedThreat(
                    threat_type=(
                        ThreatType
                        .UNKNOWN_FORMAT
                    ),
                    description=(
                        "File is not a valid "
                        "TAR archive"
                    ),
                    score=20,
                    file_path=archive_path,
                )
            ]

        threats: list[
            DetectedThreat
        ] = []

        try:
            with tarfile.open(
                archive_path,
                "r:*",
            ) as archive:
                members = (
                    archive.getmembers()
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
                                member.name
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

                    if (
                        member.issym()
                        or member.islnk()
                    ):
                        threats.append(
                            DetectedThreat(
                                threat_type=(
                                    ThreatType
                                    .UNSAFE_PATH
                                ),
                                description=(
                                    "Archive contains "
                                    "symbolic or hard "
                                    "link: "
                                    f"{member.name}"
                                ),
                                score=40,
                                file_path=(
                                    archive_path
                                ),
                            )
                        )

                    if (
                        member.isdev()
                        or member.isfifo()
                    ):
                        threats.append(
                            DetectedThreat(
                                threat_type=(
                                    ThreatType
                                    .UNSAFE_PATH
                                ),
                                description=(
                                    "Archive contains "
                                    "special device "
                                    "entry: "
                                    f"{member.name}"
                                ),
                                score=50,
                                file_path=(
                                    archive_path
                                ),
                            )
                        )

        except (
            OSError,
            tarfile.TarError,
        ) as error:
            return [
                DetectedThreat(
                    threat_type=(
                        ThreatType
                        .UNKNOWN_FORMAT
                    ),
                    description=(
                        "Unable to inspect "
                        "TAR archive: "
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

        with tarfile.open(
            archive_path,
            "r:*",
        ) as archive:
            members = (
                archive.getmembers()
            )

            self._raise_if_limits_exceeded(
                archive_path,
                members,
            )

            for member in members:
                if not member.isfile():
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
                            member.name
                        ),
                    )
                )

                if (
                    threat is not None
                    or target_path is None
                ):
                    continue

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

                source = (
                    archive.extractfile(
                        member
                    )
                )

                if source is None:
                    continue

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
                    with source:
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
            tarfile.TarInfo
        ],
    ) -> list[DetectedThreat]:
        threats: list[
            DetectedThreat
        ] = []

        file_members = [
            member
            for member in members
            if member.isfile()
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
            member.size
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

        try:
            compressed_size = (
                archive_path
                .stat()
                .st_size
            )

        except OSError:
            compressed_size = 0

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

        return threats

    def _raise_if_limits_exceeded(
        self,
        archive_path: Path,
        members: list[
            tarfile.TarInfo
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