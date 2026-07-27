import signal
import tkinter as tk

from application.action_service import (
    ActionService,
)
from application.quarantine_manager import (
    QuarantineManager,
)
from application.reporting_service import (
    ReportingService,
)
from application.scanner_service import (
    ScannerService,
)
from config import AppConfig
from infrastructure.downloads_watcher import (
    DownloadsWatcher,
)
from infrastructure.history_storage import (
    HistoryStorage,
)
from infrastructure.local_quarantine import (
    LocalQuarantineProvider,
)
from infrastructure.report_writer import (
    ReportWriter,
)
from infrastructure.single_instance import (
    SingleInstanceLock,
)
from platform_services.notifier_factory import (
    NotifierFactory,
)
from platform_services.system_security.security_factory import (
    SystemSecurityFactory,
)
from presentation.action_window import (
    ActionWindow,
    ScanResultQueue,
)
from utils.logger import (
    setup_logger,
)


def main() -> None:
    AppConfig.validate()
    AppConfig.prepare_dirs()

    logger = setup_logger()

    instance_lock = SingleInstanceLock(
        AppConfig.DATA_DIR
        / "application.lock"
    )

    if not instance_lock.acquire():
        logger.warning(
            "Application start cancelled "
            "because another instance "
            "is already running."
        )
        return

    logger.info(
        "Application started"
    )

    root: tk.Tk | None = None
    watcher: DownloadsWatcher | None = None
    action_window: ActionWindow | None = None

    shutting_down = False

    try:
        root = tk.Tk()
        root.withdraw()

        scanner = ScannerService()

        notifier = (
            NotifierFactory.create()
        )

        report_writer = (
            ReportWriter(
                reports_dir=(
                    AppConfig.REPORTS_DIR
                )
            )
        )

        history_storage = (
            HistoryStorage(
                scan_history_path=(
                    AppConfig
                    .REPORT_HISTORY_FILE
                ),
                action_history_path=(
                    AppConfig
                    .ACTION_HISTORY_FILE
                ),
            )
        )

        reporting_service = (
            ReportingService(
                report_writer=(
                    report_writer
                ),
                history_storage=(
                    history_storage
                ),
            )
        )

        system_security = (
            SystemSecurityFactory
            .create()
        )

        local_quarantine = (
            LocalQuarantineProvider(
                quarantine_dir=(
                    AppConfig
                    .QUARANTINE_DIR
                )
            )
        )

        quarantine_manager = (
            QuarantineManager(
                system_provider=(
                    system_security
                ),
                local_provider=(
                    local_quarantine
                ),
            )
        )

        action_service = (
            ActionService(
                reporting_service=(
                    reporting_service
                ),
                quarantine_provider=(
                    quarantine_manager
                ),
            )
        )

        result_queue = ScanResultQueue()

        action_window = (
            ActionWindow(
                root=root,
                result_queue=(
                    result_queue
                ),
                action_service=(
                    action_service
                ),
            )
        )

        watcher = (
            DownloadsWatcher(
                scanner=scanner,
                notifier=notifier,
                reporting_service=(
                    reporting_service
                ),
                on_scan_completed=(
                    result_queue.put
                ),
                downloads_dir=(
                    AppConfig
                    .DOWNLOADS_DIR
                ),
            )
        )

        def shutdown(
            reason: str,
        ) -> None:
            nonlocal shutting_down

            if shutting_down:
                return

            shutting_down = True

            logger.info(
                "Application shutdown "
                "requested: %s",
                reason,
            )

            if action_window is not None:
                try:
                    action_window.stop()

                except Exception:
                    logger.exception(
                        "Unable to stop "
                        "action window."
                    )

            if watcher is not None:
                try:
                    watcher.stop()

                except Exception:
                    logger.exception(
                        "Unable to stop "
                        "downloads watcher."
                    )

            if root is not None:
                try:
                    root.quit()

                except tk.TclError:
                    pass

        def request_shutdown_from_signal(
            signum,
            frame,
        ) -> None:
            if root is None:
                return

            try:
                root.after(
                    0,
                    lambda: shutdown(
                        f"signal {signum}"
                    ),
                )

            except tk.TclError:
                pass

        root.protocol(
            "WM_DELETE_WINDOW",
            lambda: shutdown(
                "window close"
            ),
        )

        try:
            signal.signal(
                signal.SIGINT,
                request_shutdown_from_signal,
            )

        except (
            ValueError,
            OSError,
        ):
            pass

        if hasattr(
            signal,
            "SIGTERM",
        ):
            try:
                signal.signal(
                    signal.SIGTERM,
                    request_shutdown_from_signal,
                )

            except (
                ValueError,
                OSError,
            ):
                pass

        watcher.start()
        action_window.start()

        root.mainloop()

    except KeyboardInterrupt:
        logger.info(
            "Application interrupted "
            "by user."
        )

    except Exception:
        logger.exception(
            "Fatal application error."
        )
        raise

    finally:
        if action_window is not None:
            try:
                action_window.stop()

            except Exception:
                logger.exception(
                    "Unable to stop "
                    "action window during "
                    "final cleanup."
                )

        if watcher is not None:
            try:
                watcher.stop()

            except Exception:
                logger.exception(
                    "Unable to stop "
                    "downloads watcher "
                    "during final cleanup."
                )

        if root is not None:
            try:
                root.destroy()

            except tk.TclError:
                pass

        instance_lock.release()

        logger.info(
            "Application stopped"
        )


if __name__ == "__main__":
    main()