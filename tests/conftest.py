from pathlib import Path

import pytest


@pytest.fixture
def safe_text_file(
    tmp_path: Path,
) -> Path:
    file_path = tmp_path / "safe.txt"

    file_path.write_text(
        "This is a normal text file.",
        encoding="utf-8",
    )

    return file_path


@pytest.fixture
def suspicious_script(
    tmp_path: Path,
) -> Path:
    file_path = tmp_path / "danger.ps1"

    file_path.write_text(
        "powershell -EncodedCommand test",
        encoding="utf-8",
    )

    return file_path


@pytest.fixture
def windows_executable_file(
    tmp_path: Path,
) -> Path:
    file_path = tmp_path / "program.exe"

    file_path.write_bytes(
        b"MZ" + b"\x00" * 256
    )

    return file_path


@pytest.fixture
def macos_executable_file(
    tmp_path: Path,
) -> Path:
    file_path = tmp_path / "program.bin"

    file_path.write_bytes(
        b"\xcf\xfa\xed\xfe"
        + b"\x00" * 256
    )

    return file_path


@pytest.fixture
def suspicious_text_file(
    tmp_path: Path,
) -> Path:
    file_path = tmp_path / "suspicious.txt"

    file_path.write_text(
        (
            "powershell "
            "cmd.exe "
            "CreateRemoteThread "
            "VirtualAlloc "
            "WriteProcessMemory "
            "base64 "
            "eval("
        ),
        encoding="utf-8",
    )

    return file_path