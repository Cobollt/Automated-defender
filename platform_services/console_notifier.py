from platform_services.base_notifier import BaseNotifier
from utils.logger import setup_logger


class ConsoleNotifier(BaseNotifier):
    def __init__(self) -> None:
        self._logger = setup_logger()

    def notify(
        self,
        title: str,
        message: str,
    ) -> bool:
        print()
        print("=" * 50)
        print(title)
        print("-" * 50)
        print(message)
        print("=" * 50)

        self._logger.info(
            "Console notification: %s | %s",
            title,
            message.replace("\n", " | "),
        )

        return True