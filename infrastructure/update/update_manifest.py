import platform
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from packaging.version import (
    InvalidVersion,
    Version,
)


SHA256_PATTERN = re.compile(
    r"^[0-9a-fA-F]{64}$"
)


class UpdateError(Exception):
    pass


@dataclass(frozen=True)
class PlatformUpdate:
    url: str
    sha256: str

    def __post_init__(
        self,
    ) -> None:
        validate_http_url(
            self.url
        )

        normalized_sha256 = (
            self.sha256
            .strip()
            .lower()
        )

        if not SHA256_PATTERN.fullmatch(
            normalized_sha256
        ):
            raise UpdateError(
                "В манифесте указан "
                "некорректный SHA-256."
            )

        object.__setattr__(
            self,
            "sha256",
            normalized_sha256,
        )


@dataclass(frozen=True)
class UpdateManifest:
    version: str
    published_at: str
    windows: (
        PlatformUpdate | None
    )
    macos: (
        PlatformUpdate | None
    )

    @classmethod
    def from_dict(
        cls,
        data: dict[
            str,
            Any,
        ],
    ) -> "UpdateManifest":
        if not isinstance(
            data,
            dict,
        ):
            raise UpdateError(
                "Манифест имеет "
                "некорректный формат."
            )

        version = str(
            data.get(
                "version",
                "",
            )
        ).strip()

        if not version:
            raise UpdateError(
                "В манифесте "
                "отсутствует версия."
            )

        validate_version(
            version
        )

        published_at = str(
            data.get(
                "published_at",
                "",
            )
        ).strip()

        windows = (
            parse_platform_update(
                data.get(
                    "windows"
                )
            )
        )

        macos = (
            parse_platform_update(
                data.get(
                    "macos"
                )
            )
        )

        if (
            windows is None
            and macos is None
        ):
            raise UpdateError(
                "В манифесте "
                "отсутствуют пакеты "
                "обновления."
            )

        return cls(
            version=version,
            published_at=(
                published_at
            ),
            windows=windows,
            macos=macos,
        )

    def platform_update(
        self,
        system_name: (
            str | None
        ) = None,
    ) -> PlatformUpdate:
        current_system = (
            system_name
            or platform.system()
        )

        if (
            current_system
            == "Windows"
        ):
            update = (
                self.windows
            )

        elif (
            current_system
            == "Darwin"
        ):
            update = (
                self.macos
            )

        else:
            raise UpdateError(
                "Обновление "
                "поддерживается только "
                "на Windows и macOS."
            )

        if update is None:
            raise UpdateError(
                "Для этой платформы "
                "обновление отсутствует "
                "в манифесте."
            )

        return update


def parse_platform_update(
    data: Any,
) -> PlatformUpdate | None:
    if data is None:
        return None

    if not isinstance(
        data,
        dict,
    ):
        raise UpdateError(
            "Секция платформы "
            "в манифесте имеет "
            "некорректный формат."
        )

    url = str(
        data.get(
            "url",
            "",
        )
    ).strip()

    sha256 = str(
        data.get(
            "sha256",
            "",
        )
    ).strip()

    return PlatformUpdate(
        url=url,
        sha256=sha256,
    )


def validate_http_url(
    value: str,
) -> None:
    parsed = urlparse(
        value
    )

    if (
        parsed.scheme
        not in {
            "http",
            "https",
        }
    ):
        raise UpdateError(
            "В манифесте "
            "указан некорректный "
            "URL обновления."
        )

    if not parsed.netloc:
        raise UpdateError(
            "В манифесте "
            "указан некорректный "
            "URL обновления."
        )


def validate_version(
    version: str,
) -> Version:
    normalized = (
        version
        .strip()
        .lstrip("v")
    )

    if not normalized:
        raise UpdateError(
            "Пустая версия."
        )

    try:
        return Version(
            normalized
        )

    except InvalidVersion as error:
        raise UpdateError(
            "Некорректная версия: "
            f"{version}"
        ) from error


def is_newer_version(
    current_version: str,
    remote_version: str,
) -> bool:
    current = (
        validate_version(
            current_version
        )
    )

    remote = (
        validate_version(
            remote_version
        )
    )

    return remote > current