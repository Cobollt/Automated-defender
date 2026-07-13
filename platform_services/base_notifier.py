from abc import abstractmethod

from domain.enums import RiskLevel, ScanStatus
from domain.interfaces import NotifierInterface
from domain.models import ScanResult


class BaseNotifier(NotifierInterface):
    @abstractmethod
    def notify(
        self,
        title: str,
        message: str,
    ) -> bool:
        pass

    def notify_scan_result(
        self,
        result: ScanResult,
    ) -> bool:
        title = self._build_title(result)
        message = self._build_message(result)

        return self.notify(
            title=title,
            message=message,
        )

    def _build_title(self, result: ScanResult) -> str:
        if result.status == ScanStatus.FAILED:
            return "AntiArchiveScanner — ошибка"

        titles = {
            RiskLevel.SAFE: "Файл безопасен",
            RiskLevel.LOW: "Обнаружен низкий риск",
            RiskLevel.MEDIUM: "Файл подозрительный",
            RiskLevel.HIGH: "Обнаружена высокая угроза",
            RiskLevel.CRITICAL: "Обнаружена критическая угроза",
        }

        return titles.get(
            result.risk_level,
            "Проверка завершена",
        )

    def _build_message(self, result: ScanResult) -> str:
        file_name = result.target_path.name

        if result.status == ScanStatus.FAILED:
            error_message = (
                result.error_message
                or "Неизвестная ошибка проверки"
            )

            return (
                f"Файл: {file_name}\n"
                f"Ошибка: {error_message}"
            )

        message_parts = [
            f"Файл: {file_name}",
            f"Уровень риска: {result.risk_level.value}",
            f"Оценка риска: {result.risk_score}/100",
            f"Проверено файлов: {result.total_files_checked}",
            f"Найдено признаков: {result.total_threats_found}",
        ]

        recommendation = self._build_recommendation(result)
        message_parts.append(recommendation)

        return "\n".join(message_parts)

    def _build_recommendation(
        self,
        result: ScanResult,
    ) -> str:
        recommendations = {
            RiskLevel.SAFE: (
                "Рекомендация: файл можно оставить."
            ),
            RiskLevel.LOW: (
                "Действия: оставить, удалить или переместить в карантин."
            ),
            RiskLevel.MEDIUM: (
                "Рекомендуется переместить файл в карантин."
            ),
            RiskLevel.HIGH: (
                "Рекомендуется немедленно переместить файл в карантин."
            ),
            RiskLevel.CRITICAL: (
                "Не открывайте файл. Переместите его в карантин или удалите."
            ),
        }

        return recommendations.get(
            result.risk_level,
            "Проверка завершена.",
        )