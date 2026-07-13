import sys
from pathlib import Path

from config import AppConfig


class ApplicationCommandBuilder:
    @staticmethod
    def executable_path() -> Path:
        return Path(sys.executable).resolve()

    @staticmethod
    def application_path() -> Path:
        if getattr(sys, "frozen", False):
            return Path(sys.executable).resolve()

        return (AppConfig.BASE_DIR / "app.py").resolve()

    @classmethod
    def build_arguments(cls) -> list[str]:
        if getattr(sys, "frozen", False):
            return [str(cls.application_path())]

        return [
            str(cls.executable_path()),
            str(cls.application_path()),
        ]

    @classmethod
    def build_windows_command(cls) -> str:
        arguments = cls.build_arguments()

        return " ".join(
            f'"{argument}"'
            for argument in arguments
        )