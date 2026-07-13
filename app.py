import tkinter as tk

from application.action_service import ActionService
from application.quarantine_manager import QuarantineManager
from application.reporting_service import ReportingService
from application.scanner_service import ScannerService
from config import AppConfig
from infrastructure.downloads_watcher import DownloadsWatcher
from infrastructure.history_storage import HistoryStorage
from infrastructure.local_quarantine import (
    LocalQuarantineProvider,
)
from infrastructure.report_writer import ReportWriter
from platform_services.notifier_factory import NotifierFactory
from platform_services.system_security.security_factory import (
    SystemSecurityFactory,
)
from presentation.action_window import (
    ActionWindow,
    ScanResultQueue,
)
from utils.logger import setup_logger


def main() -> None:
    AppConfig.prepare_dirs()

    logger = setup_logger()
    logger.info("Application started")

    root = tk.Tk()

    scanner = ScannerService()
    notifier = NotifierFactory.create()

    report_writer = ReportWriter(
        reports_dir=AppConfig.REPORTS_DIR
    )

    history_storage = HistoryStorage(
        scan_history_path=AppConfig.REPORT_HISTORY_FILE,
        action_history_path=AppConfig.ACTION_HISTORY_FILE,
    )

    reporting_service = ReportingService(
        report_writer=report_writer,
        history_storage=history_storage,
    )

    system_security = SystemSecurityFactory.create()

    local_quarantine = LocalQuarantineProvider(
        quarantine_dir=AppConfig.QUARANTINE_DIR
    )

    quarantine_manager = QuarantineManager(
        system_provider=system_security,
        local_provider=local_quarantine,
    )

    action_service = ActionService(
        reporting_service=reporting_service,
        quarantine_provider=quarantine_manager,
    )

    result_queue = ScanResultQueue()

    ActionWindow(
        root=root,
        result_queue=result_queue,
        action_service=action_service,
    )

    watcher = DownloadsWatcher(
        scanner=scanner,
        notifier=notifier,
        reporting_service=reporting_service,
        on_scan_completed=result_queue.put,
        downloads_dir=AppConfig.DOWNLOADS_DIR,
    )

    def shutdown() -> None:
        logger.info(
            "Application shutdown requested"
        )

        watcher.stop()
        root.destroy()

    root.protocol(
        "WM_DELETE_WINDOW",
        shutdown,
    )

    notifier.notify(
        title="AntiArchiveScanner",
        message=(
            "Программа запущена.\n"
            "Папка Downloads находится под наблюдением."
        ),
    )

    watcher.start()

    try:
        root.mainloop()

    finally:
        watcher.stop()
        logger.info("Application stopped")


if __name__ == "__main__":
    main()