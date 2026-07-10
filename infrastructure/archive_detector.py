from pathlib import Path


class ArchiveDetector:
    ARCHIVE_EXTENSIONS = {
        ".zip",
        ".tar",
        ".gz",
        ".tgz",
        ".bz2",
        ".xz",
        ".7z",
        ".rar",
    }

    ZIP_MAGIC = b"PK\x03\x04"

    def is_archive(self, file_path: Path) -> bool:
        if file_path.suffix.lower() in self.ARCHIVE_EXTENSIONS:
            return True

        try:
            with file_path.open("rb") as file:
                header = file.read(4)
        except OSError:
            return False

        return header.startswith(self.ZIP_MAGIC)