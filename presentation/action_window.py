import queue
import tkinter as tk
from tkinter import messagebox

from domain.enums import (
    FileAction,
    RiskLevel,
)
from domain.interfaces import (
    ActionServiceInterface,
)
from domain.models import ScanResult
from utils.logger import setup_logger


DANGEROUS_RISK_LEVELS = {
    RiskLevel.HIGH,
    RiskLevel.CRITICAL,
}


class ScanResultQueue:
    def __init__(self) -> None:
        self._queue: queue.Queue[
            ScanResult
        ] = queue.Queue()

    def put(
        self,
        result: ScanResult,
    ) -> None:
        self._queue.put(
            result
        )

    def get_nowait(
        self,
    ) -> ScanResult:
        return self._queue.get_nowait()

    def empty(
        self,
    ) -> bool:
        return self._queue.empty()


class ActionWindow:
    POLL_INTERVAL_MS = 250

    def __init__(
        self,
        root: tk.Tk,
        result_queue: ScanResultQueue,
        action_service: ActionServiceInterface,
    ) -> None:
        self._root = root

        self._result_queue = (
            result_queue
        )

        self._action_service = (
            action_service
        )

        self._logger = setup_logger()

        self._active_window: (
            tk.Toplevel | None
        ) = None

        self._running = False

        self._poll_after_id: (
            str | None
        ) = None

    def start(
        self,
    ) -> None:
        if self._running:
            return

        self._running = True

        self._schedule_poll()

    def stop(
        self,
    ) -> None:
        self._running = False

        if (
            self._poll_after_id
            is not None
        ):
            try:
                self._root.after_cancel(
                    self._poll_after_id
                )

            except tk.TclError:
                pass

            self._poll_after_id = None

        if (
            self._active_window
            is not None
        ):
            try:
                if (
                    self._active_window
                    .winfo_exists()
                ):
                    self._active_window.destroy()

            except tk.TclError:
                pass

            self._active_window = None

    def _schedule_poll(
        self,
    ) -> None:
        if not self._running:
            return

        self._poll_after_id = (
            self._root.after(
                self.POLL_INTERVAL_MS,
                self._poll_queue,
            )
        )

    def _poll_queue(
        self,
    ) -> None:
        self._poll_after_id = None

        if not self._running:
            return

        if (
            self._active_window
            is not None
        ):
            try:
                if (
                    self._active_window
                    .winfo_exists()
                ):
                    self._schedule_poll()
                    return

            except tk.TclError:
                pass

            self._active_window = None

        try:
            while True:
                result = (
                    self._result_queue
                    .get_nowait()
                )

                if (
                    result.risk_level
                    not in DANGEROUS_RISK_LEVELS
                ):
                    self._logger.debug(
                        "Ignoring non-dangerous "
                        "result in action window: "
                        "file=%s risk_level=%s",
                        result.target_path,
                        result.risk_level.value,
                    )

                    continue

                self._show_result_window(
                    result
                )

                break

        except queue.Empty:
            pass

        self._schedule_poll()

    def _show_result_window(
        self,
        scan_result: ScanResult,
    ) -> None:
        if (
            self._active_window
            is not None
        ):
            return

        window = tk.Toplevel(
            self._root
        )

        self._active_window = window

        window.title(
            "AntiArchiveScanner"
        )

        window.resizable(
            False,
            False,
        )

        window.attributes(
            "-topmost",
            True,
        )

        window.protocol(
            "WM_DELETE_WINDOW",
            lambda: self._keep_and_close(
                scan_result=scan_result,
                window=window,
            ),
        )

        content = tk.Frame(
            window,
            padx=20,
            pady=20,
        )

        content.pack(
            fill="both",
            expand=True,
        )

        title_label = tk.Label(
            content,
            text=self._risk_title(
                scan_result.risk_level
            ),
            font=(
                "Arial",
                16,
                "bold",
            ),
        )

        title_label.pack(
            pady=(0, 10)
        )

        information = (
            f"Файл: "
            f"{scan_result.target_path.name}\n"

            f"Путь: "
            f"{scan_result.target_path}\n"

            f"SHA-256: "
            f"{scan_result.target_sha256 or 'не вычислен'}\n"

            f"Уровень риска: "
            f"{scan_result.risk_level.value}\n"

            f"Оценка риска: "
            f"{scan_result.risk_score}/100\n"

            f"Проверено файлов: "
            f"{scan_result.total_files_checked}\n"

            f"Найдено признаков: "
            f"{scan_result.total_threats_found}"
        )

        info_label = tk.Label(
            content,
            text=information,
            justify="left",
            anchor="w",
            wraplength=620,
        )

        info_label.pack(
            pady=(0, 15)
        )

        recommendation_label = tk.Label(
            content,
            text=self._recommendation(
                scan_result.risk_level
            ),
            justify="left",
            wraplength=620,
        )

        recommendation_label.pack(
            pady=(0, 20)
        )

        buttons = tk.Frame(
            content
        )

        buttons.pack()

        keep_button = tk.Button(
            buttons,
            text="Оставить",
            width=18,
            command=lambda: (
                self._execute_action(
                    action=FileAction.KEEP,
                    scan_result=scan_result,
                    window=window,
                )
            ),
        )

        keep_button.grid(
            row=0,
            column=0,
            padx=5,
        )

        delete_button = tk.Button(
            buttons,
            text="Удалить",
            width=18,
            command=lambda: (
                self._confirm_delete(
                    scan_result=scan_result,
                    window=window,
                )
            ),
        )

        delete_button.grid(
            row=0,
            column=1,
            padx=5,
        )

        quarantine_button = tk.Button(
            buttons,
            text="Переместить в карантин",
            width=24,
            command=lambda: (
                self._execute_action(
                    action=FileAction.QUARANTINE,
                    scan_result=scan_result,
                    window=window,
                )
            ),
        )

        quarantine_button.grid(
            row=0,
            column=2,
            padx=5,
        )

        window.update_idletasks()

        screen_width = (
            window.winfo_screenwidth()
        )

        screen_height = (
            window.winfo_screenheight()
        )

        width = (
            window.winfo_width()
        )

        height = (
            window.winfo_height()
        )

        x = max(
            (
                screen_width
                - width
            )
            // 2,
            0,
        )

        y = max(
            (
                screen_height
                - height
            )
            // 2,
            0,
        )

        window.geometry(
            f"+{x}+{y}"
        )

        window.lift()

        window.focus_force()

        self._logger.info(
            "Action window opened: "
            "file=%s "
            "risk_level=%s "
            "risk_score=%s",
            scan_result.target_path,
            scan_result.risk_level.value,
            scan_result.risk_score,
        )

    def _confirm_delete(
        self,
        scan_result: ScanResult,
        window: tk.Toplevel,
    ) -> None:
        if not self._is_active_window(
            window
        ):
            return

        confirmed = (
            messagebox.askyesno(
                title=(
                    "Подтверждение удаления"
                ),
                message=(
                    "Удалить файл без возможности "
                    "восстановления?\n\n"
                    f"{scan_result.target_path}"
                ),
                parent=window,
            )
        )

        if not confirmed:
            return

        self._execute_action(
            action=FileAction.DELETE,
            scan_result=scan_result,
            window=window,
        )

    def _execute_action(
        self,
        action: FileAction,
        scan_result: ScanResult,
        window: tk.Toplevel,
    ) -> None:
        if not self._is_active_window(
            window
        ):
            return

        try:
            action_result = (
                self._action_service.execute(
                    action=action,
                    scan_result=scan_result,
                )
            )

        except Exception as error:
            self._logger.exception(
                "Unexpected action error: "
                "file=%s action=%s",
                scan_result.target_path,
                action.value,
            )

            messagebox.showerror(
                title="Ошибка",
                message=(
                    "Не удалось выполнить "
                    f"действие: {error}"
                ),
                parent=window,
            )

            return

        if action_result.success:
            messagebox.showinfo(
                title="Действие выполнено",
                message=(
                    action_result.message
                ),
                parent=window,
            )

            self._close_window(
                window
            )

            return

        messagebox.showerror(
            title="Ошибка",
            message=action_result.message,
            parent=window,
        )

    def _keep_and_close(
        self,
        scan_result: ScanResult,
        window: tk.Toplevel,
    ) -> None:
        if not self._is_active_window(
            window
        ):
            return

        try:
            action_result = (
                self._action_service.execute(
                    action=FileAction.KEEP,
                    scan_result=scan_result,
                )
            )

            if not action_result.success:
                messagebox.showerror(
                    title="Ошибка",
                    message=(
                        action_result.message
                    ),
                    parent=window,
                )

                return

        except Exception as error:
            self._logger.exception(
                "Unexpected keep action "
                "error: file=%s",
                scan_result.target_path,
            )

            messagebox.showerror(
                title="Ошибка",
                message=(
                    "Не удалось сохранить "
                    f"действие: {error}"
                ),
                parent=window,
            )

            return

        self._close_window(
            window
        )

    def _close_window(
        self,
        window: tk.Toplevel,
    ) -> None:
        if not self._is_active_window(
            window
        ):
            return

        try:
            window.destroy()

        except tk.TclError:
            pass

        self._active_window = None

        if self._running:
            self._root.after_idle(
                self._poll_queue
            )

    def _is_active_window(
        self,
        window: tk.Toplevel,
    ) -> bool:
        if (
            self._active_window
            is not window
        ):
            return False

        try:
            return bool(
                window.winfo_exists()
            )

        except tk.TclError:
            return False

    @staticmethod
    def _risk_title(
        risk_level: RiskLevel,
    ) -> str:
        titles = {
            RiskLevel.HIGH: (
                "Высокий уровень риска"
            ),
            RiskLevel.CRITICAL: (
                "Критическая угроза"
            ),
        }

        return titles.get(
            risk_level,
            (
                "Обнаружена "
                "потенциальная угроза"
            ),
        )

    @staticmethod
    def _recommendation(
        risk_level: RiskLevel,
    ) -> str:
        recommendations = {
            RiskLevel.HIGH: (
                "Не открывайте файл. "
                "Рекомендуется переместить "
                "его в карантин или удалить."
            ),
            RiskLevel.CRITICAL: (
                "Не открывайте файл. "
                "Рекомендуется немедленно "
                "переместить его в карантин "
                "или удалить."
            ),
        }

        return recommendations.get(
            risk_level,
            "Выберите безопасное действие.",
        )