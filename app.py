from application.scanner_service import ScannerService
from infrastructure.downloads_watcher import DownloadsWatcher
from utils.logger import setup_logger


def main() -> None:
    logger = setup_logger()
    logger.info("Application started")

    scanner = ScannerService()
    watcher = DownloadsWatcher(scanner)

    watcher.start()


if __name__ == "__main__":
    main()