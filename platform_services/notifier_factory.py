import platform

from domain.interfaces import NotifierInterface
from platform_services.console_notifier import ConsoleNotifier
from platform_services.macos_notifier import MacOSNotifier
from platform_services.windows_notifier import WindowsNotifier


class NotifierFactory:
    @staticmethod
    def create() -> NotifierInterface:
        system_name = platform.system().lower()

        if system_name == "darwin":
            return MacOSNotifier()

        if system_name == "windows":
            return WindowsNotifier()

        return ConsoleNotifier()