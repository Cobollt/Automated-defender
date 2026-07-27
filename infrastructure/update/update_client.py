import json
import urllib.error
import urllib.request
from pathlib import Path

from infrastructure.update.update_config import (
    BUFFER_SIZE,
    DOWNLOAD_TIMEOUT_SECONDS,
)
from infrastructure.update.update_manifest import (
    UpdateError,
    UpdateManifest,
)
from utils.hashing import (
    calculate_sha256,
)


class UpdateClient:
    def __init__(
        self,
        manifest_url: str,
    ) -> None:
        self._manifest_url = (
            manifest_url
        )

    def fetch_manifest(
        self,
    ) -> UpdateManifest:
        request = (
            urllib.request.Request(
                self._manifest_url,
                headers={
                    "User-Agent": (
                        "AntiArchiveScanner-Updater"
                    ),
                    "Accept": (
                        "application/json"
                    ),
                },
            )
        )

        try:
            with (
                urllib.request
                .urlopen(
                    request,
                    timeout=(
                        DOWNLOAD_TIMEOUT_SECONDS
                    ),
                )
            ) as response:
                raw_data = (
                    response.read()
                )

        except (
            urllib.error.HTTPError
        ) as error:
            raise UpdateError(
                "Сервер обновлений "
                "вернул HTTP "
                f"{error.code}."
            ) from error

        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
        ) as error:
            raise UpdateError(
                "Не удалось загрузить "
                "манифест обновления: "
                f"{error}"
            ) from error

        try:
            decoded = (
                raw_data.decode(
                    "utf-8"
                )
            )

            data = json.loads(
                decoded
            )

        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as error:
            raise UpdateError(
                "Манифест "
                "обновления повреждён."
            ) from error

        if not isinstance(
            data,
            dict,
        ):
            raise UpdateError(
                "Манифест имеет "
                "некорректный формат."
            )

        return (
            UpdateManifest
            .from_dict(
                data
            )
        )

    def download_update(
        self,
        url: str,
        expected_sha256: str,
        destination: Path,
    ) -> None:
        destination = Path(
            destination
        )

        destination.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        temporary_path = (
            destination.with_name(
                destination.name
                + ".part"
            )
        )

        temporary_path.unlink(
            missing_ok=True
        )

        request = (
            urllib.request.Request(
                url,
                headers={
                    "User-Agent": (
                        "AntiArchiveScanner-Updater"
                    ),
                },
            )
        )

        try:
            with (
                urllib.request
                .urlopen(
                    request,
                    timeout=(
                        DOWNLOAD_TIMEOUT_SECONDS
                    ),
                )
            ) as response:
                with (
                    temporary_path
                    .open(
                        "wb"
                    )
                ) as output_file:
                    while True:
                        chunk = (
                            response.read(
                                BUFFER_SIZE
                            )
                        )

                        if not chunk:
                            break

                        output_file.write(
                            chunk
                        )

            actual_sha256 = (
                calculate_sha256(
                    temporary_path
                )
            )

            if (
                actual_sha256.lower()
                != expected_sha256
                .lower()
            ):
                raise UpdateError(
                    "SHA-256 обновления "
                    "не совпадает. "
                    "Файл удалён."
                )

            temporary_path.replace(
                destination
            )

        except UpdateError:
            temporary_path.unlink(
                missing_ok=True
            )

            destination.unlink(
                missing_ok=True
            )

            raise

        except (
            urllib.error.HTTPError
        ) as error:
            temporary_path.unlink(
                missing_ok=True
            )

            destination.unlink(
                missing_ok=True
            )

            raise UpdateError(
                "Сервер обновлений "
                "вернул HTTP "
                f"{error.code}."
            ) from error

        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
        ) as error:
            temporary_path.unlink(
                missing_ok=True
            )

            destination.unlink(
                missing_ok=True
            )

            raise UpdateError(
                "Не удалось загрузить "
                "обновление: "
                f"{error}"
            ) from error