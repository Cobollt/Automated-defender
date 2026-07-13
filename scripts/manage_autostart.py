import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from platform_services.autostart.autostart_factory import (
    AutostartFactory,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Управление автозапуском AntiArchiveScanner"
    )

    parser.add_argument(
        "action",
        choices={
            "enable",
            "disable",
            "status",
        },
    )

    arguments = parser.parse_args()

    service = AutostartFactory.create()

    if arguments.action == "enable":
        success = service.enable()

        print(
            "Автозапуск включён."
            if success
            else "Не удалось включить автозапуск."
        )

        raise SystemExit(0 if success else 1)

    if arguments.action == "disable":
        success = service.disable()

        print(
            "Автозапуск отключён."
            if success
            else "Не удалось отключить автозапуск."
        )

        raise SystemExit(0 if success else 1)

    enabled = service.is_enabled()

    print(
        "Автозапуск включён."
        if enabled
        else "Автозапуск отключён."
    )


if __name__ == "__main__":
    main()