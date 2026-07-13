import platform

from domain.interfaces import SystemSecurityProviderInterface
from platform_services.system_security.macos_security import (
    MacOSSecurityProvider,
)
from platform_services.system_security.unsupported_security import (
    UnsupportedSecurityProvider,
)
from platform_services.system_security.windows_defender import (
    WindowsDefenderProvider,
)


class SystemSecurityFactory:
    @staticmethod
    def create() -> SystemSecurityProviderInterface:
        system_name = platform.system().lower()

        if system_name == "windows":
            return WindowsDefenderProvider()

        if system_name == "darwin":
            return MacOSSecurityProvider()

        return UnsupportedSecurityProvider()