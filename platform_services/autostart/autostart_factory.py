import platform

from domain.interfaces import AutostartServiceInterface
from platform_services.autostart.macos_autostart import (
    MacOSAutostartService,
)
from platform_services.autostart.unsupported_autostart import (
    UnsupportedAutostartService,
)
from platform_services.autostart.windows_autostart import (
    WindowsAutostartService,
)


class AutostartFactory:
    @staticmethod
    def create() -> AutostartServiceInterface:
        system_name = platform.system().lower()

        if system_name == "darwin":
            return MacOSAutostartService()

        if system_name == "windows":
            return WindowsAutostartService()

        return UnsupportedAutostartService()