import os
from pathlib import Path

import pytest

from infrastructure.single_instance import (
    SingleInstanceError,
    SingleInstanceLock,
)


def test_first_instance_acquires_lock(
    tmp_path: Path,
) -> None:
    lock_path = (
        tmp_path
        / "application.lock"
    )

    lock = SingleInstanceLock(
        lock_path
    )

    try:
        assert (
            lock.acquire()
            is True
        )

        assert (
            lock.acquired
            is True
        )

        assert (
            lock_path.exists()
        )

    finally:
        lock.release()


def test_second_instance_cannot_acquire_same_lock(
    tmp_path: Path,
) -> None:
    lock_path = (
        tmp_path
        / "application.lock"
    )

    first = (
        SingleInstanceLock(
            lock_path
        )
    )

    second = (
        SingleInstanceLock(
            lock_path
        )
    )

    try:
        assert (
            first.acquire()
            is True
        )

        assert (
            second.acquire()
            is False
        )

        assert (
            first.acquired
            is True
        )

        assert (
            second.acquired
            is False
        )

    finally:
        second.release()
        first.release()


def test_lock_can_be_acquired_after_first_instance_releases(
    tmp_path: Path,
) -> None:
    lock_path = (
        tmp_path
        / "application.lock"
    )

    first = (
        SingleInstanceLock(
            lock_path
        )
    )

    second = (
        SingleInstanceLock(
            lock_path
        )
    )

    assert (
        first.acquire()
        is True
    )

    assert (
        second.acquire()
        is False
    )

    first.release()

    try:
        assert (
            second.acquire()
            is True
        )

        assert (
            second.acquired
            is True
        )

    finally:
        second.release()


def test_repeated_acquire_on_same_instance_is_idempotent(
    tmp_path: Path,
) -> None:
    lock = SingleInstanceLock(
        tmp_path
        / "application.lock"
    )

    try:
        assert (
            lock.acquire()
            is True
        )

        assert (
            lock.acquire()
            is True
        )

        assert (
            lock.acquired
            is True
        )

    finally:
        lock.release()


def test_repeated_release_is_safe(
    tmp_path: Path,
) -> None:
    lock = SingleInstanceLock(
        tmp_path
        / "application.lock"
    )

    assert (
        lock.acquire()
        is True
    )

    lock.release()
    lock.release()

    assert (
        lock.acquired
        is False
    )


def test_acquire_or_raise_raises_for_second_instance(
    tmp_path: Path,
) -> None:
    lock_path = (
        tmp_path
        / "application.lock"
    )

    first = (
        SingleInstanceLock(
            lock_path
        )
    )

    second = (
        SingleInstanceLock(
            lock_path
        )
    )

    try:
        first.acquire_or_raise()

        with pytest.raises(
            SingleInstanceError
        ):
            second.acquire_or_raise()

    finally:
        second.release()
        first.release()


def test_context_manager_releases_lock(
    tmp_path: Path,
) -> None:
    lock_path = (
        tmp_path
        / "application.lock"
    )

    with SingleInstanceLock(
        lock_path
    ) as first:
        assert (
            first.acquired
            is True
        )

        second = (
            SingleInstanceLock(
                lock_path
            )
        )

        try:
            assert (
                second.acquire()
                is False
            )

        finally:
            second.release()

    third = (
        SingleInstanceLock(
            lock_path
        )
    )

    try:
        assert (
            third.acquire()
            is True
        )

    finally:
        third.release()


def test_lock_file_contains_current_process_id(
    tmp_path: Path,
) -> None:
    lock_path = (
        tmp_path
        / "application.lock"
    )

    lock = (
        SingleInstanceLock(
            lock_path
        )
    )

    assert (
        lock.acquire()
        is True
    )

    assert (
        lock.acquired
        is True
    )

    # На Windows msvcrt.locking()
    # может запрещать чтение файла
    # через второй дескриптор,
    # пока блокировка удерживается.
    #
    # Поэтому сначала освобождаем lock,
    # затем проверяем записанный PID.
    lock.release()

    assert (
        lock.acquired
        is False
    )

    owner_pid = (
        lock_path
        .read_text(
            encoding="utf-8"
        )
        .strip()
    )

    assert (
        owner_pid
        == str(
            os.getpid()
        )
    )


def test_existing_unlocked_file_does_not_block_start(
    tmp_path: Path,
) -> None:
    lock_path = (
        tmp_path
        / "application.lock"
    )

    # Имитируем lock-файл,
    # оставшийся после старого
    # завершившегося процесса.
    lock_path.write_text(
        "999999\n",
        encoding="utf-8",
    )

    lock = (
        SingleInstanceLock(
            lock_path
        )
    )

    assert (
        lock.acquire()
        is True
    )

    assert (
        lock.acquired
        is True
    )

    # Сам факт существования файла
    # не должен мешать получению
    # системной блокировки.
    lock.release()

    # После освобождения lock
    # можно безопасно проверить,
    # что старый PID был заменён.
    assert (
        lock_path
        .read_text(
            encoding="utf-8"
        )
        .strip()
        == str(
            os.getpid()
        )
    )


def test_parent_directory_is_created_automatically(
    tmp_path: Path,
) -> None:
    lock_path = (
        tmp_path
        / "nested"
        / "state"
        / "application.lock"
    )

    assert (
        not lock_path.parent.exists()
    )

    lock = (
        SingleInstanceLock(
            lock_path
        )
    )

    try:
        assert (
            lock.acquire()
            is True
        )

        assert (
            lock_path.parent.exists()
        )

    finally:
        lock.release()