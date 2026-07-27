from dataclasses import dataclass


@dataclass(frozen=True)
class FileSignature:
    name: str
    is_executable: bool = False
    is_archive: bool = False
    is_document: bool = False


class FileTypeDetector:
    SIGNATURES = {
        b"MZ": FileSignature(
            name="Windows executable PE",
            is_executable=True,
        ),
        b"\x7fELF": FileSignature(
            name="Linux executable ELF",
            is_executable=True,
        ),
        b"\xcf\xfa\xed\xfe": FileSignature(
            name="macOS Mach-O",
            is_executable=True,
        ),
        b"\xfe\xed\xfa\xcf": FileSignature(
            name="macOS Mach-O",
            is_executable=True,
        ),
        b"\xce\xfa\xed\xfe": FileSignature(
            name="macOS Mach-O 32-bit",
            is_executable=True,
        ),
        b"\xfe\xed\xfa\xce": FileSignature(
            name="macOS Mach-O 32-bit",
            is_executable=True,
        ),
        b"\xca\xfe\xba\xbe": FileSignature(
            name="macOS Universal Binary",
            is_executable=True,
        ),
        b"\xbe\xba\xfe\xca": FileSignature(
            name="macOS Universal Binary",
            is_executable=True,
        ),
        b"PK\x03\x04": FileSignature(
            name=(
                "ZIP or Office "
                "Open XML archive"
            ),
            is_archive=True,
        ),
        b"PK\x05\x06": FileSignature(
            name="Empty ZIP archive",
            is_archive=True,
        ),
        b"PK\x07\x08": FileSignature(
            name="Spanned ZIP archive",
            is_archive=True,
        ),
        b"Rar!\x1a\x07\x00": FileSignature(
            name="RAR archive version 4",
            is_archive=True,
        ),
        b"Rar!\x1a\x07\x01\x00": FileSignature(
            name="RAR archive version 5",
            is_archive=True,
        ),
        b"7z\xbc\xaf\x27\x1c": FileSignature(
            name="7-Zip archive",
            is_archive=True,
        ),
        b"\x1f\x8b": FileSignature(
            name="GZIP archive",
            is_archive=True,
        ),
        b"BZh": FileSignature(
            name="BZIP2 archive",
            is_archive=True,
        ),
        b"\xfd7zXZ\x00": FileSignature(
            name="XZ archive",
            is_archive=True,
        ),
        b"%PDF": FileSignature(
            name="PDF document",
            is_document=True,
        ),
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": (
            FileSignature(
                name=(
                    "Microsoft "
                    "Compound File"
                ),
                is_document=True,
            )
        ),
        b"{\\rtf": FileSignature(
            name="RTF document",
            is_document=True,
        ),
        b"\x89PNG\r\n\x1a\n": FileSignature(
            name="PNG image",
        ),
        b"\xff\xd8\xff": FileSignature(
            name="JPEG image",
        ),
        b"GIF87a": FileSignature(
            name="GIF image",
        ),
        b"GIF89a": FileSignature(
            name="GIF image",
        ),
    }

    ORDERED_SIGNATURES = tuple(
        sorted(
            SIGNATURES.items(),
            key=lambda item: len(
                item[0]
            ),
            reverse=True,
        )
    )

    @classmethod
    def detect(
        cls,
        data: bytes,
    ) -> FileSignature | None:
        if not data:
            return None

        for (
            signature,
            file_signature,
        ) in cls.ORDERED_SIGNATURES:
            if data.startswith(
                signature
            ):
                return file_signature

        if cls._is_tar(
            data
        ):
            return FileSignature(
                name="TAR archive",
                is_archive=True,
            )

        return None

    @staticmethod
    def _is_tar(
        data: bytes,
    ) -> bool:
        tar_magic_offset = 257
        tar_magic = b"ustar"

        end_offset = (
            tar_magic_offset
            + len(tar_magic)
        )

        if (
            len(data)
            < end_offset
        ):
            return False

        return (
            data[
                tar_magic_offset:
                end_offset
            ]
            == tar_magic
        )