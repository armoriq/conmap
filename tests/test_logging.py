import logging

from conmap.logging import (
    get_logger,
    get_progress_backlog,
    publish_progress_message,
    register_progress_listener,
    set_log_level,
    unregister_progress_listener,
)


def test_progress_listener_captures_messages():
    queue, history = register_progress_listener(include_history=False)
    assert history == []
    publish_progress_message("first")
    publish_progress_message("second")
    assert queue.get(timeout=0.1) == "first"
    assert queue.get(timeout=0.1) == "second"
    unregister_progress_listener(queue)
    backlog = get_progress_backlog()
    assert "first" in backlog
    assert "second" in backlog


def test_logger_configuration_and_set_level():
    logger = get_logger("conmap.tests.logging")
    logger.info("initial message")
    set_log_level(logging.ERROR)
    root = get_logger()
    assert root.level == logging.ERROR
