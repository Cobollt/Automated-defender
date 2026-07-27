import shutil
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from config import AppConfig


class TempManager:
    def __init__(
        self,
        root_dir: Path | None = None,
        prefix: str | None = None,
        max_age_seconds: int | None = None,
    ) -> None:
        self._root_dir = (
            root_dir
            if root_dir is not None
            else AppConfig.TEMP_DIR
        ).resolve()

        self._prefix = (
            prefix
            if prefix is not None
            else AppConfig.TEMP_DIRECTORY_PREFIX
        )

        self._max_age_seconds = (
            max_age_seconds
            if max_age_seconds is not None
            else AppConfig.TEMP_DIRECTORY_MAX_AGE_SECONDS
        )

        self._validate_settings()

        self._root_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

    @property
    def root_dir(self) -> Path:
        return self._root_dir

    def create_temp_dir(self) -> Path:
        self._root_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        return Path(
            tempfile.mkdtemp(
                prefix=self._prefix,
                dir=self._root_dir,
            )
        )

    @contextmanager
    def temporary_directory(
        self,
    ) -> Iterator[Path]:
        temp_dir = (
            self.create_temp_dir()
        )

        try:
            yield temp_dir

        finally:
            self.cleanup(
                temp_dir
            )

    def cleanup(
        self,
        temp_dir: Path,
    ) -> None:
        temp_dir = Path(
            temp_dir
        )

        if not self._is_managed_path(
            temp_dir
        ):
            raise ValueError(
                "Refusing to remove a "
                "directory that is not "
                "managed by "
                "AntiArchiveScanner: "
                f"{temp_dir}"
            )

        if (
            not temp_dir.exists()
            and not temp_dir.is_symlink()
        ):
            return

        if temp_dir.is_symlink():
            temp_dir.unlink(
                missing_ok=True
            )

            return

        shutil.rmtree(
            temp_dir,
            ignore_errors=False,
        )

    def cleanup_stale(
        self,
    ) -> int:
        self._root_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        removed = 0

        current_time = (
            time.time()
        )

        for candidate in (
            self._root_dir.iterdir()
        ):
            if not (
                candidate.name.startswith(
                    self._prefix
                )
            ):
                continue

            if not self._is_managed_path(
                candidate
            ):
                continue

            try:
                modified_at = (
                    candidate
                    .lstat()
                    .st_mtime
                )

            except OSError:
                continue

            age_seconds = (
                current_time
                - modified_at
            )

            if (
                age_seconds
                < self._max_age_seconds
            ):
                continue

            try:
                self.cleanup(
                    candidate
                )

            except OSError:
                continue

            removed += 1

        return removed

    def _is_managed_path(
        self,
        path: Path,
    ) -> bool:
        path = Path(
            path
        )

        try:
            parent = (
                path.parent.resolve()
            )

        except OSError:
            return False

        return (
            parent == self._root_dir
            and path.name.startswith(
                self._prefix
            )
            and path.name
            != self._prefix
        )

    def _validate_settings(
        self,
    ) -> None:
        if not self._prefix:
            raise ValueError(
                "Temporary directory "
                "prefix cannot be empty."
            )

        if (
            Path(self._prefix).name
            != self._prefix
        ):
            raise ValueError(
                "Temporary directory "
                "prefix must not contain "
                "path separators."
            )

        if (
            self._max_age_seconds
            <= 0
        ):
            raise ValueError(
                "Temporary directory "
                "maximum age must be "
                "positive."
            )