
APP_NAME = "AntiArchiveScanner"

CURRENT_VERSION = "1.0.0"

GITHUB_OWNER = "Cobollt"
GITHUB_REPOSITORY = "Automated-defender"
GITHUB_BRANCH = "main"

RAW_BASE_URL = (
    "https://raw.githubusercontent.com/"
    f"{GITHUB_OWNER}/"
    f"{GITHUB_REPOSITORY}/"
    f"{GITHUB_BRANCH}"
)

UPDATE_MANIFEST_URL = (
    f"{RAW_BASE_URL}/"
    "release/update-manifest.json"
)

WINDOWS_INSTALLER_URL = (
    f"{RAW_BASE_URL}/"
    "release/windows/"
    "AntiArchiveScanner-Setup.exe"
)

MACOS_INSTALLER_URL = (
    f"{RAW_BASE_URL}/"
    "release/macos/"
    "AntiArchiveScanner.dmg"
)

DOWNLOAD_TIMEOUT_SECONDS = 60

BUFFER_SIZE = 1024 * 1024