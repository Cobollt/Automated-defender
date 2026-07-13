from pathlib import Path

from domain.interfaces import SystemSecurityProviderInterface
from domain.models import SystemSecurityResult


class UnsupportedSecurityProvider(
    SystemSecurityProviderInterface
):
    PROVIDER_NAME = "Unsupported system security"

    def report_and_quarantine(
        self,
        file_path: Path,
    ) -> SystemSecurityResult:
        return SystemSecurityResult(
            success=False,
            provider_name=self.PROVIDER_NAME,
            file_path=file_path,
            message=(
                "Системная защита этой операционной системы "
                "не поддерживается."
            ),
        )