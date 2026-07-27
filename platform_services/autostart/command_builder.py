import os
import shlex
import sys
from pathlib import Path

from config import AppConfig


class ApplicationCommandBuilder:
    @staticmethod
    def executable_path() -> Path:
        return Path(
            sys.executable
        ).resolve()

    @staticmethod
    def source_entry_path() -> Path:
        return (
            AppConfig.SOURCE_DIR
            / "app.py"
        ).resolve()

    @classmethod
    def build_arguments(
        cls,
    ) -> list[str]:
        if AppConfig.is_frozen():
            return [
                str(
                    cls.executable_path()
                )
            ]

        return [
            str(
                cls.executable_path()
            ),
            str(
                cls.source_entry_path()
            ),
        ]

    @classmethod
    def build_windows_command(
        cls,
    ) -> str:
        return subprocess_list2cmdline(
            cls.build_arguments()
        )

    @classmethod
    def build_macos_program_arguments(
        cls,
    ) -> list[str]:
        return cls.build_arguments()

    @classmethod
    def working_directory(
        cls,
    ) -> Path:
        if AppConfig.is_frozen():
            return (
                cls.executable_path()
                .parent
            )

        return (
            AppConfig.SOURCE_DIR
            .resolve()
        )

    @classmethod
    def display_command(
        cls,
    ) -> str:
        if os.name == "nt":
            return (
                cls.build_windows_command()
            )

        return " ".join(
            shlex.quote(
                argument
            )
            for argument
            in cls.build_arguments()
        )


def subprocess_list2cmdline(
    arguments: list[str],
) -> str:
    """
    Формирует Windows command line
    по тем же правилам, которые использует
    subprocess.list2cmdline(), но без
    необходимости запускать процесс.
    """
    import subprocess

    return subprocess.list2cmdline(
        arguments
    )