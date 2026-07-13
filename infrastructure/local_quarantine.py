import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from config import AppConfig
from domain.interfaces import QuarantineProviderInterface
from domain.models import QuarantineResult
from utils.hashing import calculate_sha256
from utils.logger import setup_logger


class LocalQuarantineProvider(
    QuarantineProviderInterface
):
    PROVIDER_NAME = "AntiArchiveScanner Local Quarantine"

    def __init__(
        self,
        quarantine_dir: Path | None = None,
    ) -> None:
        self._quarantine_dir = (
            quarantine_dir or AppConfig.QUARANTINE_DIR
        )
        self._logger = setup_logger()

    def quarantine(
        self,
        file_path: Path,
    ) -> QuarantineResult:
        if not file_path.exists():
            return QuarantineResult(
                success=False,
                provider_name=self.PROVIDER_NAME,
                original_path=file_path,
                message="Файл не существует.",
            )

        if not file_path.is_file():
            return QuarantineResult(
                success=False,
                provider_name=self.PROVIDER_NAME,
                original_path=file_path,
                message=(
                    "В карантин можно перемещать "
                    "только обычные файлы."
                ),
            )

        self._quarantine_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        try:
            sha256 = calculate_sha256(file_path)
            quarantine_id = uuid4().hex

            stored_name = (
                f"{quarantine_id}"
                f"{AppConfig.QUARANTINE_FILE_EXTENSION}"
            )

            quarantine_path = (
                self._quarantine_dir
                / stored_name
            )

            metadata_path = (
                self._quarantine_dir
                / (
                    quarantine_id
                    + AppConfig.QUARANTINE_METADATA_EXTENSION
                )
            )

            metadata = {
                "quarantine_id": quarantine_id,
                "original_name": file_path.name,
                "original_path": str(file_path.resolve()),
                "stored_name": stored_name,
                "sha256": sha256,
                "quarantined_at": datetime.now(
                    timezone.utc
                ).isoformat(),
                "provider": self.PROVIDER_NAME,
            }

            shutil.move(
                str(file_path),
                str(quarantine_path),
            )

            try:
                metadata_path.write_text(
                    json.dumps(
                        metadata,
                        ensure_ascii=False,
                        indent=2,
                    ),
                    encoding="utf-8",
                )

            except Exception:
                self._rollback_move(
                    quarantine_path=quarantine_path,
                    original_path=file_path,
                )
                raise

            self._restrict_permissions(
                quarantine_path
            )

            self._logger.warning(
                "File moved to local quarantine: %s -> %s",
                file_path,
                quarantine_path,
            )

            return QuarantineResult(
                success=True,
                provider_name=self.PROVIDER_NAME,
                original_path=file_path,
                quarantine_path=quarantine_path,
                message=(
                    "Системная защита не подтвердила карантин. "
                    "Файл перемещён в локальный карантин приложения."
                ),
            )

        except (OSError, PermissionError) as error:
            self._logger.exception(
                "Unable to quarantine file: %s",
                file_path,
            )

            return QuarantineResult(
                success=False,
                provider_name=self.PROVIDER_NAME,
                original_path=file_path,
                message=(
                    "Не удалось переместить файл "
                    f"в локальный карантин: {error}"
                ),
            )

    def _restrict_permissions(
        self,
        quarantine_path: Path,
    ) -> None:
        try:
            quarantine_path.chmod(0o600)
        except OSError as error:
            self._logger.warning(
                "Unable to restrict quarantine file "
                "permissions: %s",
                error,
            )

    def _rollback_move(
        self,
        quarantine_path: Path,
        original_path: Path,
    ) -> None:
        if (
            quarantine_path.exists()
            and not original_path.exists()
        ):
            shutil.move(
                str(quarantine_path),
                str(original_path),
            )