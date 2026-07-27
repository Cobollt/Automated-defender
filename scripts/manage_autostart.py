#!/usr/bin/env python3

import argparse
import platform
import sys
from pathlib import Path


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parent
    .parent
)

project_root_string = str(
    PROJECT_ROOT
)

if (
    project_root_string
    not in sys.path
):
    sys.path.insert(
        0,
        project_root_string,
    )


from platform_services.autostart.autostart_factory import (
    AutostartFactory,
)
from platform_services.autostart.command_builder import (
    ApplicationCommandBuilder,
)
from platform_services.autostart.macos_autostart import (
    MacOSAutostartService,
)
from platform_services.autostart.windows_autostart import (
    WindowsAutostartService,
)


def parse_arguments(
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Управление автозапуском "
            "AntiArchiveScanner."
        )
    )

    parser.add_argument(
        "action",
        choices=(
            "enable",
            "disable",
            "status",
        ),
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help=(
            "Показать команду и "
            "служебные пути."
        ),
    )

    return parser.parse_args()


def print_environment_info(
    service,
) -> None:
    print()
    print(
        "Платформа:",
        platform.system(),
    )

    print(
        "Команда запуска:",
        (
            ApplicationCommandBuilder
            .display_command()
        ),
    )

    print(
        "Рабочий каталог:",
        (
            ApplicationCommandBuilder
            .working_directory()
        ),
    )

    if isinstance(
        service,
        MacOSAutostartService,
    ):
        print(
            "LaunchAgent:",
            service.plist_path,
        )

    elif isinstance(
        service,
        WindowsAutostartService,
    ):
        print(
            "Registry:",
            (
                "HKCU\\"
                + service.REGISTRY_PATH
            ),
        )

        current_command = (
            service.current_command()
        )

        print(
            "Текущее значение:",
            (
                current_command
                or "отсутствует"
            ),
        )


def enable_autostart(
    service,
) -> int:
    if service.is_enabled():
        print(
            "Автозапуск уже включён."
        )

        return 0

    success = service.enable()

    if not success:
        print(
            "Не удалось включить "
            "автозапуск."
        )

        return 1

    if not service.is_enabled():
        print(
            "Автозапуск был создан, "
            "но итоговая проверка "
            "не пройдена."
        )

        return 1

    print(
        "Автозапуск включён."
    )

    return 0


def disable_autostart(
    service,
) -> int:
    if not service.is_enabled():
        # disable всё равно вызываем,
        # потому что конфигурация могла
        # существовать, но быть устаревшей.
        success = service.disable()

        if success:
            print(
                "Автозапуск уже "
                "отключён."
            )

            return 0

        print(
            "Не удалось очистить "
            "конфигурацию "
            "автозапуска."
        )

        return 1

    success = service.disable()

    if not success:
        print(
            "Не удалось отключить "
            "автозапуск."
        )

        return 1

    if service.is_enabled():
        print(
            "Автозапуск всё ещё "
            "активен после "
            "отключения."
        )

        return 1

    print(
        "Автозапуск отключён."
    )

    return 0


def show_status(
    service,
) -> int:
    enabled = (
        service.is_enabled()
    )

    print(
        (
            "Автозапуск включён."
            if enabled
            else (
                "Автозапуск "
                "отключён."
            )
        )
    )

    return 0


def main(
) -> int:
    arguments = (
        parse_arguments()
    )

    service = (
        AutostartFactory.create()
    )

    if arguments.verbose:
        print_environment_info(
            service
        )

        print()

    if (
        arguments.action
        == "enable"
    ):
        return enable_autostart(
            service
        )

    if (
        arguments.action
        == "disable"
    ):
        return disable_autostart(
            service
        )

    return show_status(
        service
    )


if __name__ == "__main__":
    raise SystemExit(
        main()
    )