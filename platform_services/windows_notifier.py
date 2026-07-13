import base64
import subprocess
from xml.sax.saxutils import escape

from platform_services.base_notifier import BaseNotifier
from utils.logger import setup_logger


class WindowsNotifier(BaseNotifier):
    APP_ID = "AntiArchiveScanner"

    def __init__(self) -> None:
        self._logger = setup_logger()

    def notify(
        self,
        title: str,
        message: str,
    ) -> bool:
        toast_xml = self._build_toast_xml(
            title=title,
            message=message,
        )

        powershell_script = self._build_powershell_script(
            toast_xml=toast_xml,
        )

        encoded_command = base64.b64encode(
            powershell_script.encode("utf-16-le")
        ).decode("ascii")

        try:
            result = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-EncodedCommand",
                    encoded_command,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
                creationflags=self._creation_flags(),
            )

            if result.returncode != 0:
                self._logger.error(
                    "Windows notification failed: %s",
                    result.stderr.strip(),
                )
                return False

            self._logger.info(
                "Windows notification sent: %s",
                title,
            )

            return True

        except (
            OSError,
            subprocess.SubprocessError,
        ) as error:
            self._logger.error(
                "Unable to send Windows notification: %s",
                error,
            )
            return False

    def _build_toast_xml(
        self,
        title: str,
        message: str,
    ) -> str:
        safe_title = escape(title)
        safe_message = escape(message)

        return (
            "<toast>"
            "<visual>"
            '<binding template="ToastGeneric">'
            f"<text>{safe_title}</text>"
            f"<text>{safe_message}</text>"
            "</binding>"
            "</visual>"
            "</toast>"
        )

    def _build_powershell_script(
        self,
        toast_xml: str,
    ) -> str:
        escaped_xml = toast_xml.replace(
            "'",
            "''",
        )

        return f"""
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] > $null

$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml('{escaped_xml}')

$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)

$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{self.APP_ID}')
$notifier.Show($toast)
"""

    def _creation_flags(self) -> int:
        try:
            return subprocess.CREATE_NO_WINDOW
        except AttributeError:
            return 0