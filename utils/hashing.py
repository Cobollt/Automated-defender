import hashlib
from pathlib import Path


HASH_CHUNK_SIZE = (
    1024 * 1024
)


def calculate_sha256(
    file_path: Path,
) -> str:
    file_path = Path(
        file_path
    )

    if not file_path.exists():
        raise FileNotFoundError(
            "File does not exist: "
            f"{file_path}"
        )

    if not file_path.is_file():
        raise ValueError(
            "SHA256 can be "
            "calculated only for "
            "regular files: "
            f"{file_path}"
        )

    digest = (
        hashlib.sha256()
    )

    with file_path.open(
        "rb"
    ) as file:
        for chunk in iter(
            lambda: file.read(
                HASH_CHUNK_SIZE
            ),
            b"",
        ):
            digest.update(
                chunk
            )

    return digest.hexdigest()