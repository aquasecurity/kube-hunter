from kube_hunter.conf.__init__ import logging,setup_logger

def test_setup_logger():
    test_cases = [
        ("NONE", 50),
        ("INFO", 20),
        ("DEBUG", 10),
        ("CRITICAL", 50),
        ("GIBRISH", 20)
    ]
    for test_log_level_name, expected in test_cases:
        setup_logger(test_log_level_name)
        assert type(logging.getLogger().getEffectiveLevel()) is expected
