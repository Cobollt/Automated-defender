import shutil
import tempfile
from pathlib import Path


class TempManager:
    def create_temp_dir(self) -> Path:
        return Path(tempfile.mkdtemp(prefix="anti_archive_scanner_"))

    def cleanup(self, temp_dir: Path) -> None:
        if temp_dir.exists():
            shutil.rmtree(str(temp_dir), ignore_errors=True)