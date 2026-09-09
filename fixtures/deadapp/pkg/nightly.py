"""Scheduled job. Nothing imports it; cron runs it via `python -m pkg.nightly`."""


def run() -> str:
    return "nightly report"


REPORT = run()
