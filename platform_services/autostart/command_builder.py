import sys
from pathlib import Path

from config import AppConfig


class ApplicationCommandBuilder:
    @staticmethod
    def executable_path() -> Path:
        return Path(sys.executable).resolve()

    @staticmethod
    def source_entry_path() -> Path:
        return (
            AppConfig.SOURCE_DIR
            / "app.py"
        ).resolve()

    @classmethod
    def build_arguments(cls) -> list[str]:
        if AppConfig.is_frozen():
            return [
                str(cls.executable_path())
            ]

        return [
            str(cls.executable_path()),
            str(cls.source_entry_path()),
        ]

    @classmethod
    def build_windows_command(cls) -> str:
        return " ".join(
            cls._quote_windows_argument(argument)
            for argument in cls.build_arguments()
        )

    @classmethod
    def build_macos_program_arguments(
        cls,
    ) -> list[str]:
        return cls.build_arguments()

    @classmethod
    def working_directory(cls) -> Path:
        if AppConfig.is_frozen():
            return cls.executable_path().parent

        return AppConfig.SOURCE_DIR.resolve()

    @staticmethod
    def _quote_windows_argument(
        argument: str,
    ) -> str:
        escaped_argument = argument.replace(
            '"',
            '\\"',
        )

        return f'"{escaped_argument}"'