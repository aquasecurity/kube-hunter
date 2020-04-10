import logging

from kube_hunter.conf.logging import setup_logger


def test_setup_logger_level():
    test_cases = [
        ("INFO", logging.INFO),
        ("Debug", logging.DEBUG),
        ("critical", logging.CRITICAL),
        ("NOTEXISTS", logging.INFO),
        ("BASIC_FORMAT", logging.INFO),
    ]
    for level, expected in test_cases:
        setup_logger(level)
        actual = logging.getLogger().getEffectiveLevel()
        assert actual == expected, f"{level} level should be {expected} (got {actual})"


def test_setup_logger_none():
    setup_logger("NONE")
    assert logging.getLogger().manager.disable == logging.CRITICAL
