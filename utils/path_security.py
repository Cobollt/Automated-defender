from pathlib import Path, PurePosixPath, PureWindowsPath


def normalize_archive_member_name(
    member_name: str,
) -> PurePosixPath | None:
    if (
        not isinstance(member_name, str)
        or not member_name
    ):
        return None

    if "\x00" in member_name:
        return None

    normalized = member_name.replace(
        "\\",
        "/",
    )

    posix_path = PurePosixPath(
        normalized
    )

    windows_path = PureWindowsPath(
        member_name
    )

    if (
        posix_path.is_absolute()
        or windows_path.is_absolute()
    ):
        return None

    if windows_path.drive:
        return None

    if any(
        part == ".."
        for part in posix_path.parts
    ):
        return None

    return posix_path


def build_safe_extract_path(
    base_dir: Path,
    member_name: str,
) -> Path | None:
    normalized_member = (
        normalize_archive_member_name(
            member_name
        )
    )

    if normalized_member is None:
        return None

    base_dir = base_dir.resolve()

    target_path = (
        base_dir
        / Path(
            *normalized_member.parts
        )
    ).resolve()

    if not is_safe_extract_path(
        base_dir,
        target_path,
    ):
        return None

    return target_path


def is_safe_extract_path(
    base_dir: Path,
    target_path: Path,
) -> bool:
    base_dir = base_dir.resolve()
    target_path = target_path.resolve()

    try:
        target_path.relative_to(
            base_dir
        )

        return True

    except ValueError:
        return False