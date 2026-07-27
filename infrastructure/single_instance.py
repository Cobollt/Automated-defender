import os
from pathlib import Path
from typing import IO


class SingleInstanceError(
    RuntimeError
):
    pass


class SingleInstanceLock:
    def __init__(
        self,
        lock_path: Path,
    ) -> None:
        self._lock_path = Path(
            lock_path
        )

        self._file: (
            IO[str] | None
        ) = None

        self._acquired = False

    @property
    def lock_path(
        self,
    ) -> Path:
        return self._lock_path

    @property
    def acquired(
        self,
    ) -> bool:
        return self._acquired

    def acquire(
        self,
    ) -> bool:
        if self._acquired:
            return True

        self._lock_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        lock_file = (
            self._lock_path.open(
                "a+",
                encoding="utf-8",
            )
        )

        try:
            self._lock_file(
                lock_file
            )

        except (
            BlockingIOError,
            OSError,
        ):
            lock_file.close()

            return False

        self._file = lock_file
        self._acquired = True

        self._write_owner_pid()

        return True

    def acquire_or_raise(
        self,
    ) -> None:
        if self.acquire():
            return

        raise SingleInstanceError(
            "AntiArchiveScanner "
            "is already running."
        )

    def release(
        self,
    ) -> None:
        if (
            not self._acquired
            or self._file is None
        ):
            return

        lock_file = self._file

        self._file = None
        self._acquired = False

        try:
            self._unlock_file(
                lock_file
            )

        finally:
            lock_file.close()

    def __enter__(
        self,
    ) -> "SingleInstanceLock":
        self.acquire_or_raise()

        return self

    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback,
    ) -> None:
        self.release()

    def _write_owner_pid(
        self,
    ) -> None:
        if self._file is None:
            return

        self._file.seek(0)
        self._file.truncate()

        self._file.write(
            str(
                os.getpid()
            )
        )

        self._file.write(
            "\n"
        )

        self._file.flush()

        try:
            os.fsync(
                self._file.fileno()
            )

        except OSError:
            pass

    @staticmethod
    def _lock_file(
        lock_file: IO[str],
    ) -> None:
        if os.name == "nt":
            import msvcrt

            lock_file.seek(0)

            if (
                lock_file.read(1)
                == ""
            ):
                lock_file.seek(0)

                lock_file.write(
                    "0"
                )

                lock_file.flush()

            lock_file.seek(0)

            msvcrt.locking(
                lock_file.fileno(),
                msvcrt.LK_NBLCK,
                1,
            )

            return

        import fcntl

        fcntl.flock(
            lock_file.fileno(),
            (
                fcntl.LOCK_EX
                | fcntl.LOCK_NB
            ),
        )

    @staticmethod
    def _unlock_file(
        lock_file: IO[str],
    ) -> None:
        if os.name == "nt":
            import msvcrt

            lock_file.seek(0)

            try:
                msvcrt.locking(
                    lock_file.fileno(),
                    msvcrt.LK_UNLCK,
                    1,
                )

            except OSError:
                pass

            return

        import fcntl

        try:
            fcntl.flock(
                lock_file.fileno(),
                fcntl.LOCK_UN,
            )

        except OSError:
            pass