from __future__ import annotations

import logging
from collections import deque
from queue import Queue
from threading import Lock
from typing import Deque, List, Optional, Tuple

ProgressQueue = Queue[str]

_BROADCAST_LOCK = Lock()
_PROGRESS_SUBSCRIBERS: List[ProgressQueue] = []
_PROGRESS_BACKLOG: Deque[str] = deque(maxlen=200)


def publish_progress_message(message: str) -> None:
    with _BROADCAST_LOCK:
        _PROGRESS_BACKLOG.append(message)
        subscribers = list(_PROGRESS_SUBSCRIBERS)
    for queue in subscribers:
        queue.put(message)


def register_progress_listener(include_history: bool = True) -> Tuple[ProgressQueue, List[str]]:
    queue: ProgressQueue = Queue()
    with _BROADCAST_LOCK:
        _PROGRESS_SUBSCRIBERS.append(queue)
        history = list(_PROGRESS_BACKLOG) if include_history else []
    return queue, history


def unregister_progress_listener(queue: ProgressQueue) -> None:
    with _BROADCAST_LOCK:
        if queue in _PROGRESS_SUBSCRIBERS:
            _PROGRESS_SUBSCRIBERS.remove(queue)


def get_progress_backlog() -> List[str]:
    with _BROADCAST_LOCK:
        return list(_PROGRESS_BACKLOG)


class ProgressLogHandler(logging.Handler):
    """Mirror log records onto the progress stream."""

    def emit(self, record: logging.LogRecord) -> None:  # pragma: no cover - exercised indirectly
        try:
            message = self.format(record)
        except Exception:
            self.handleError(record)
            return
        publish_progress_message(message)


def get_logger(name: Optional[str] = None) -> logging.Logger:
    root = logging.getLogger("conmap")
    if not root.handlers:
        formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        handler.setLevel(logging.INFO)
        root.addHandler(handler)
        progress_handler = ProgressLogHandler()
        progress_handler.setFormatter(formatter)
        progress_handler.setLevel(logging.DEBUG)
        root.addHandler(progress_handler)
        root.setLevel(logging.DEBUG)
        root.propagate = False
    else:
        formatter = root.handlers[0].formatter or logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        )
        if not any(isinstance(h, ProgressLogHandler) for h in root.handlers):
            progress_handler = ProgressLogHandler()
            progress_handler.setFormatter(formatter)
            progress_handler.setLevel(logging.DEBUG)
            root.addHandler(progress_handler)
    return logging.getLogger(name or "conmap")


def set_log_level(level: int) -> None:
    logging.getLogger("conmap").setLevel(level)
