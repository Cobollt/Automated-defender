import subprocess

from platform_services.base_notifier import BaseNotifier
from utils.logger import setup_logger


class MacOSNotifier(BaseNotifier):
    def __init__(self) -> None:
        self._logger = setup_logger()

    def notify(
        self,
        title: str,
        message: str,
    ) -> bool:
        script = (
            "display notification "
            f"{self._to_applescript_string(message)} "
            "with title "
            f"{self._to_applescript_string(title)} "
            'sound name "Glass"'
        )

        try:
            result = subprocess.run(
                [
                    "osascript",
                    "-e",
                    script,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                self._logger.error(
                    "macOS notification failed: %s",
                    result.stderr.strip(),
                )
                return False

            self._logger.info(
                "macOS notification sent: %s",
                title,
            )

            return True

        except (
            OSError,
            subprocess.SubprocessError,
        ) as error:
            self._logger.error(
                "Unable to send macOS notification: %s",
                error,
            )
            return False

    def _to_applescript_string(
        self,
        value: str,
    ) -> str:
        escaped_value = (
            value
            .replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\r", "")
            .replace("\n", "\\n")
        )

        return f'"{escaped_value}"'