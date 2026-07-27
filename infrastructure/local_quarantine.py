import json
import os
import shutil
from datetime import (
    datetime,
    timezone,
)
from pathlib import Path
from uuid import uuid4

from config import AppConfig
from domain.interfaces import (
    QuarantineProviderInterface,
)
from domain.models import (
    QuarantineResult,
)
from utils.hashing import (
    calculate_sha256,
)
from utils.logger import setup_logger


class LocalQuarantineProvider(
    QuarantineProviderInterface
):
    PROVIDER_NAME = (
        "AntiArchiveScanner "
        "Local Quarantine"
    )

    def __init__(
        self,
        quarantine_dir: (
            Path | None
        ) = None,
    ) -> None:
        self._quarantine_dir = Path(
            quarantine_dir
            or AppConfig.QUARANTINE_DIR
        )

        self._logger = setup_logger()

    @property
    def quarantine_dir(
        self,
    ) -> Path:
        return self._quarantine_dir

    def quarantine(
        self,
        file_path: Path,
    ) -> QuarantineResult:
        file_path = Path(
            file_path
        )

        validation_error = (
            self._validate_source(
                file_path
            )
        )

        if validation_error:
            return QuarantineResult(
                success=False,
                provider_name=(
                    self.PROVIDER_NAME
                ),
                original_path=file_path,
                quarantine_path=None,
                message=validation_error,
            )

        try:
            self._prepare_directory()

        except OSError as error:
            return self._failure(
                file_path=file_path,
                message=(
                    "Не удалось подготовить "
                    "каталог карантина: "
                    f"{error}"
                ),
            )

        original_path = (
            file_path.resolve()
        )

        quarantine_path: (
            Path | None
        ) = None

        metadata_path: (
            Path | None
        ) = None

        try:
            original_sha256 = (
                calculate_sha256(
                    file_path
                )
            )

            (
                quarantine_id,
                quarantine_path,
                metadata_path,
            ) = (
                self
                ._build_unique_paths()
            )

            metadata = {
                "quarantine_id": (
                    quarantine_id
                ),
                "original_name": (
                    file_path.name
                ),
                "original_path": str(
                    original_path
                ),
                "stored_name": (
                    quarantine_path.name
                ),
                "sha256": (
                    original_sha256
                ),
                "quarantined_at": (
                    datetime.now(
                        timezone.utc
                    ).isoformat()
                ),
                "provider": (
                    self.PROVIDER_NAME
                ),
            }

            self._move_to_quarantine(
                source_path=file_path,
                quarantine_path=(
                    quarantine_path
                ),
            )

            quarantined_sha256 = (
                calculate_sha256(
                    quarantine_path
                )
            )

            if (
                quarantined_sha256
                != original_sha256
            ):
                raise OSError(
                    "SHA256 verification "
                    "failed after moving "
                    "the file to quarantine."
                )

            self._restrict_file_permissions(
                quarantine_path
            )

            self._write_metadata_atomically(
                metadata_path=(
                    metadata_path
                ),
                metadata=metadata,
            )

            self._restrict_file_permissions(
                metadata_path
            )

            self._logger.warning(
                "File moved to local "
                "quarantine: %s -> %s",
                original_path,
                quarantine_path,
            )

            return QuarantineResult(
                success=True,
                provider_name=(
                    self.PROVIDER_NAME
                ),
                original_path=(
                    original_path
                ),
                quarantine_path=(
                    quarantine_path
                ),
                message=(
                    "Системная защита "
                    "не подтвердила карантин. "
                    "Файл перемещён "
                    "в локальный карантин "
                    "приложения."
                ),
            )

        except Exception as error:
            self._logger.exception(
                "Unable to quarantine "
                "file: %s",
                original_path,
            )

            if metadata_path is not None:
                self._remove_file_safely(
                    metadata_path
                )

                temporary_metadata = (
                    self
                    ._metadata_temp_path(
                        metadata_path
                    )
                )

                self._remove_file_safely(
                    temporary_metadata
                )

            if quarantine_path is not None:
                self._rollback_move(
                    quarantine_path=(
                        quarantine_path
                    ),
                    original_path=(
                        original_path
                    ),
                )

            return self._failure(
                file_path=original_path,
                message=(
                    "Не удалось переместить "
                    "файл в локальный "
                    "карантин: "
                    f"{error}"
                ),
            )

    def _validate_source(
        self,
        file_path: Path,
    ) -> str | None:
        if not file_path.exists():
            return (
                "Файл не существует."
            )

        if file_path.is_symlink():
            return (
                "Символические ссылки "
                "нельзя помещать "
                "в карантин."
            )

        if not file_path.is_file():
            return (
                "В карантин можно "
                "перемещать только "
                "обычные файлы."
            )

        return None

    def _prepare_directory(
        self,
    ) -> None:
        if (
            self._quarantine_dir
            .exists()
            and self._quarantine_dir
            .is_symlink()
        ):
            raise OSError(
                "Quarantine directory "
                "cannot be a symbolic link."
            )

        self._quarantine_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        if (
            not self._quarantine_dir
            .is_dir()
        ):
            raise NotADirectoryError(
                "Quarantine path "
                "is not a directory."
            )

        if os.name != "nt":
            try:
                self._quarantine_dir.chmod(
                    0o700
                )

            except OSError as error:
                self._logger.warning(
                    "Unable to restrict "
                    "quarantine directory "
                    "permissions: %s",
                    error,
                )

    def _build_unique_paths(
        self,
    ) -> tuple[
        str,
        Path,
        Path,
    ]:
        while True:
            quarantine_id = (
                uuid4().hex
            )

            quarantine_path = (
                self._quarantine_dir
                / (
                    quarantine_id
                    + AppConfig
                    .QUARANTINE_FILE_EXTENSION
                )
            )

            metadata_path = (
                self._quarantine_dir
                / (
                    quarantine_id
                    + AppConfig
                    .QUARANTINE_METADATA_EXTENSION
                )
            )

            temp_metadata_path = (
                self
                ._metadata_temp_path(
                    metadata_path
                )
            )

            if (
                not quarantine_path.exists()
                and not metadata_path.exists()
                and not temp_metadata_path.exists()
            ):
                return (
                    quarantine_id,
                    quarantine_path,
                    metadata_path,
                )

    def _move_to_quarantine(
        self,
        source_path: Path,
        quarantine_path: Path,
    ) -> None:
        if quarantine_path.exists():
            raise FileExistsError(
                "Quarantine destination "
                "already exists: "
                f"{quarantine_path}"
            )

        shutil.move(
            str(source_path),
            str(quarantine_path),
        )

        if source_path.exists():
            raise OSError(
                "Source file still "
                "exists after quarantine "
                "move."
            )

        if not quarantine_path.exists():
            raise OSError(
                "Quarantine file was "
                "not created."
            )

    def _write_metadata_atomically(
        self,
        metadata_path: Path,
        metadata: dict,
    ) -> None:
        temporary_path = (
            self._metadata_temp_path(
                metadata_path
            )
        )

        self._remove_file_safely(
            temporary_path
        )

        try:
            with temporary_path.open(
                "x",
                encoding="utf-8",
            ) as target:
                json.dump(
                    metadata,
                    target,
                    ensure_ascii=False,
                    indent=2,
                )

                target.write("\n")

                target.flush()

                os.fsync(
                    target.fileno()
                )

            self._restrict_file_permissions(
                temporary_path
            )

            temporary_path.replace(
                metadata_path
            )

        except Exception:
            self._remove_file_safely(
                temporary_path
            )

            raise

    @staticmethod
    def _metadata_temp_path(
        metadata_path: Path,
    ) -> Path:
        return metadata_path.with_name(
            metadata_path.name
            + ".tmp"
        )

    def _restrict_file_permissions(
        self,
        file_path: Path,
    ) -> None:
        if os.name == "nt":
            return

        try:
            file_path.chmod(
                0o600
            )

        except OSError as error:
            self._logger.warning(
                "Unable to restrict "
                "quarantine file "
                "permissions for %s: %s",
                file_path,
                error,
            )

    def _rollback_move(
        self,
        quarantine_path: Path,
        original_path: Path,
    ) -> None:
        if not quarantine_path.exists():
            return

        if original_path.exists():
            self._logger.error(
                "Unable to roll back "
                "quarantine because "
                "original path already "
                "exists: %s",
                original_path,
            )

            return

        try:
            original_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            shutil.move(
                str(quarantine_path),
                str(original_path),
            )

            self._logger.warning(
                "Quarantine move rolled "
                "back: %s -> %s",
                quarantine_path,
                original_path,
            )

        except OSError:
            self._logger.exception(
                "Unable to roll back "
                "quarantine move: "
                "%s -> %s",
                quarantine_path,
                original_path,
            )

    @staticmethod
    def _remove_file_safely(
        file_path: Path,
    ) -> None:
        try:
            file_path.unlink(
                missing_ok=True
            )

        except OSError:
            pass

    def _failure(
        self,
        file_path: Path,
        message: str,
    ) -> QuarantineResult:
        return QuarantineResult(
            success=False,
            provider_name=(
                self.PROVIDER_NAME
            ),
            original_path=file_path,
            quarantine_path=None,
            message=message,
        )