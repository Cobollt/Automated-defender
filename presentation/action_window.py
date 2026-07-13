import queue
import tkinter as tk
from pathlib import Path
from tkinter import messagebox

from domain.enums import FileAction, RiskLevel
from domain.interfaces import ActionServiceInterface
from domain.models import ScanResult
from utils.logger import setup_logger


class ScanResultQueue:
    def __init__(self) -> None:
        self._queue: queue.Queue[ScanResult] = queue.Queue()

    def put(self, result: ScanResult) -> None:
        self._queue.put(result)

    def get_nowait(self) -> ScanResult:
        return self._queue.get_nowait()


class ActionWindow:
    POLL_INTERVAL_MS = 500

    def __init__(
        self,
        root: tk.Tk,
        result_queue: ScanResultQueue,
        action_service: ActionServiceInterface,
    ) -> None:
        self._root = root
        self._result_queue = result_queue
        self._action_service = action_service
        self._logger = setup_logger()

        self._root.withdraw()
        self._poll_queue()

    def _poll_queue(self) -> None:
        try:
            while True:
                result = self._result_queue.get_nowait()
                self._show_result_window(result)

        except queue.Empty:
            pass

        self._root.after(
            self.POLL_INTERVAL_MS,
            self._poll_queue,
        )

    def _show_result_window(
        self,
        result: ScanResult,
    ) -> None:
        window = tk.Toplevel(self._root)
        window.title("AntiArchiveScanner")
        window.resizable(False, False)

        window.protocol(
            "WM_DELETE_WINDOW",
            lambda: self._keep_and_close(
                result.target_path,
                window,
            ),
        )

        content = tk.Frame(
            window,
            padx=20,
            pady=20,
        )
        content.pack()

        title_label = tk.Label(
            content,
            text=self._risk_title(result.risk_level),
            font=("Arial", 16, "bold"),
        )
        title_label.pack(pady=(0, 10))

        information = (
            f"Файл: {result.target_path.name}\n"
            f"Путь: {result.target_path}\n"
            f"Уровень риска: {result.risk_level.value}\n"
            f"Оценка риска: {result.risk_score}/100\n"
            f"Проверено файлов: {result.total_files_checked}\n"
            f"Найдено признаков: {result.total_threats_found}"
        )

        info_label = tk.Label(
            content,
            text=information,
            justify="left",
            anchor="w",
            wraplength=520,
        )
        info_label.pack(pady=(0, 15))

        recommendation_label = tk.Label(
            content,
            text=self._recommendation(result.risk_level),
            justify="left",
            wraplength=520,
        )
        recommendation_label.pack(pady=(0, 20))

        buttons = tk.Frame(content)
        buttons.pack()

        keep_button = tk.Button(
            buttons,
            text="Оставить",
            width=18,
            command=lambda: self._execute_action(
                action=FileAction.KEEP,
                file_path=result.target_path,
                window=window,
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
            command=lambda: self._confirm_delete(
                file_path=result.target_path,
                window=window,
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
            command=lambda: self._execute_action(
                action=FileAction.QUARANTINE,
                file_path=result.target_path,
                window=window,
            ),
        )
        quarantine_button.grid(
            row=0,
            column=2,
            padx=5,
        )

        window.update_idletasks()

        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()

        width = window.winfo_width()
        height = window.winfo_height()

        x = (screen_width - width) // 2
        y = (screen_height - height) // 2

        window.geometry(f"+{x}+{y}")
        window.lift()
        window.focus_force()

    def _confirm_delete(
        self,
        file_path: Path,
        window: tk.Toplevel,
    ) -> None:
        confirmed = messagebox.askyesno(
            title="Подтверждение удаления",
            message=(
                f"Удалить файл без возможности восстановления?\n\n"
                f"{file_path}"
            ),
            parent=window,
        )

        if not confirmed:
            return

        self._execute_action(
            action=FileAction.DELETE,
            file_path=file_path,
            window=window,
        )

    def _execute_action(
        self,
        action: FileAction,
        file_path: Path,
        window: tk.Toplevel,
    ) -> None:
        result = self._action_service.execute(
            action=action,
            file_path=file_path,
        )

        if result.success:
            messagebox.showinfo(
                title="Действие выполнено",
                message=result.message,
                parent=window,
            )
            window.destroy()
            return

        messagebox.showerror(
            title="Ошибка",
            message=result.message,
            parent=window,
        )

    def _keep_and_close(
        self,
        file_path: Path,
        window: tk.Toplevel,
    ) -> None:
        self._action_service.execute(
            action=FileAction.KEEP,
            file_path=file_path,
        )
        window.destroy()

    def _risk_title(
        self,
        risk_level: RiskLevel,
    ) -> str:
        titles = {
            RiskLevel.SAFE: "Файл безопасен",
            RiskLevel.LOW: "Низкий уровень риска",
            RiskLevel.MEDIUM: "Файл подозрительный",
            RiskLevel.HIGH: "Высокий уровень риска",
            RiskLevel.CRITICAL: "Критическая угроза",
        }

        return titles.get(
            risk_level,
            "Проверка завершена",
        )

    def _recommendation(
        self,
        risk_level: RiskLevel,
    ) -> str:
        recommendations = {
            RiskLevel.SAFE: (
                "Рекомендация: файл можно оставить."
            ),
            RiskLevel.LOW: (
                "Файл содержит слабые подозрительные признаки. "
                "Выберите подходящее действие."
            ),
            RiskLevel.MEDIUM: (
                "Рекомендуется переместить файл в карантин."
            ),
            RiskLevel.HIGH: (
                "Не открывайте файл. Рекомендуется карантин или удаление."
            ),
            RiskLevel.CRITICAL: (
                "Не открывайте файл. Немедленно переместите его "
                "в карантин или удалите."
            ),
        }

        return recommendations.get(
            risk_level,
            "Выберите действие.",
        )