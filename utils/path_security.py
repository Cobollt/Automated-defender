from pathlib import Path


def is_safe_extract_path(base_dir: Path, target_path: Path) -> bool:
    base_dir = base_dir.resolve()
    target_path = target_path.resolve()

    try:
        target_path.relative_to(base_dir)
        return True
    except ValueError:
        return False