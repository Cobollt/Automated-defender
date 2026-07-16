from utils.file_type import FileTypeDetector


def test_detects_windows_pe() -> None:
    detected = FileTypeDetector.detect(
        b"MZ" + b"\x00" * 100
    )

    assert detected is not None
    assert detected.name == "Windows executable PE"
    assert detected.is_executable is True
    assert detected.is_archive is False


def test_detects_linux_elf() -> None:
    detected = FileTypeDetector.detect(
        b"\x7fELF" + b"\x00" * 100
    )

    assert detected is not None
    assert detected.name == "Linux executable ELF"
    assert detected.is_executable is True


def test_detects_macos_macho_64_bit() -> None:
    detected = FileTypeDetector.detect(
        b"\xcf\xfa\xed\xfe" + b"\x00" * 100
    )

    assert detected is not None
    assert detected.name == "macOS Mach-O"
    assert detected.is_executable is True


def test_detects_macos_macho_32_bit() -> None:
    detected = FileTypeDetector.detect(
        b"\xce\xfa\xed\xfe" + b"\x00" * 100
    )

    assert detected is not None
    assert detected.name == "macOS Mach-O 32-bit"
    assert detected.is_executable is True


def test_detects_macos_universal_binary() -> None:
    detected = FileTypeDetector.detect(
        b"\xca\xfe\xba\xbe" + b"\x00" * 100
    )

    assert detected is not None
    assert detected.name == "macOS Universal Binary"
    assert detected.is_executable is True


def test_detects_zip_archive() -> None:
    detected = FileTypeDetector.detect(
        b"PK\x03\x04" + b"\x00" * 100
    )

    assert detected is not None
    assert (
        detected.name
        == "ZIP or Office Open XML archive"
    )
    assert detected.is_archive is True
    assert detected.is_executable is False


def test_detects_empty_zip_archive() -> None:
    detected = FileTypeDetector.detect(
        b"PK\x05\x06" + b"\x00" * 100
    )

    assert detected is not None
    assert detected.name == "Empty ZIP archive"
    assert detected.is_archive is True


def test_detects_rar_version_4() -> None:
    detected = FileTypeDetector.detect(
        b"Rar!\x1a\x07\x00" + b"\x00" * 100
    )

    assert detected is not None
    assert detected.name == "RAR archive version 4"
    assert detected.is_archive is True


def test_detects_rar_version_5() -> None:
    detected = FileTypeDetector.detect(
        b"Rar!\x1a\x07\x01\x00"
        + b"\x00" * 100
    )

    assert detected is not None
    assert detected.name == "RAR archive version 5"
    assert detected.is_archive is True


def test_detects_7zip_archive() -> None:
    detected = FileTypeDetector.detect(
        b"7z\xbc\xaf\x27\x1c"
        + b"\x00" * 100
    )

    assert detected is not None
    assert detected.name == "7-Zip archive"
    assert detected.is_archive is True


def test_detects_gzip_archive() -> None:
    detected = FileTypeDetector.detect(
        b"\x1f\x8b" + b"\x00" * 100
    )

    assert detected is not None
    assert detected.name == "GZIP archive"
    assert detected.is_archive is True


def test_detects_bzip2_archive() -> None:
    detected = FileTypeDetector.detect(
        b"BZh" + b"\x00" * 100
    )

    assert detected is not None
    assert detected.name == "BZIP2 archive"
    assert detected.is_archive is True


def test_detects_xz_archive() -> None:
    detected = FileTypeDetector.detect(
        b"\xfd7zXZ\x00" + b"\x00" * 100
    )

    assert detected is not None
    assert detected.name == "XZ archive"
    assert detected.is_archive is True


def test_detects_pdf_document() -> None:
    detected = FileTypeDetector.detect(
        b"%PDF-1.7" + b"\x00" * 100
    )

    assert detected is not None
    assert detected.name == "PDF document"
    assert detected.is_document is True


def test_detects_microsoft_compound_file() -> None:
    detected = FileTypeDetector.detect(
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        + b"\x00" * 100
    )

    assert detected is not None
    assert detected.name == "Microsoft Compound File"
    assert detected.is_document is True


def test_detects_rtf_document() -> None:
    detected = FileTypeDetector.detect(
        b"{\\rtf" + b"\x00" * 100
    )

    assert detected is not None
    assert detected.name == "RTF document"
    assert detected.is_document is True


def test_detects_tar_archive_by_ustar_offset() -> None:
    data = bytearray(512)
    data[257:262] = b"ustar"

    detected = FileTypeDetector.detect(
        bytes(data)
    )

    assert detected is not None
    assert detected.name == "TAR archive"
    assert detected.is_archive is True


def test_unknown_data_returns_none() -> None:
    detected = FileTypeDetector.detect(
        b"unknown format data"
    )

    assert detected is None


def test_empty_data_returns_none() -> None:
    detected = FileTypeDetector.detect(b"")

    assert detected is None


def test_longer_signature_has_priority() -> None:
    detected = FileTypeDetector.detect(
        b"Rar!\x1a\x07\x01\x00"
        + b"\x00" * 100
    )

    assert detected is not None
    assert detected.name == "RAR archive version 5"