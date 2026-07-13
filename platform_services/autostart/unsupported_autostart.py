from domain.interfaces import AutostartServiceInterface


class UnsupportedAutostartService(
    AutostartServiceInterface
):
    def enable(self) -> bool:
        return False

    def disable(self) -> bool:
        return False

    def is_enabled(self) -> bool:
        return False