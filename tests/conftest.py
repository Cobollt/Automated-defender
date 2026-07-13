from pathlib import Path

import pytest


@pytest.fixture
def safe_text_file(tmp_path: Path) -> Path:
    file_path = tmp_path / "safe.txt"
    file_path.write_text(
        "This is a normal text file.",
        encoding="utf-8",
    )
    return file_path


@pytest.fixture
def suspicious_script(tmp_path: Path) -> Path:
    file_path = tmp_path / "danger.ps1"
    file_path.write_text(
        "powershell -EncodedCommand test",
        encoding="utf-8",
    )
    return file_path