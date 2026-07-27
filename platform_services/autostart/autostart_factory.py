import platform

from domain.interfaces import (
    AutostartServiceInterface,
)
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
    def create(
        system_name: (
            str | None
        ) = None,
    ) -> AutostartServiceInterface:
        current_system = (
            system_name
            or platform.system()
        )

        if (
            current_system
            == "Darwin"
        ):
            return (
                MacOSAutostartService()
            )

        if (
            current_system
            == "Windows"
        ):
            return (
                WindowsAutostartService()
            )

        return (
            UnsupportedAutostartService()
        )