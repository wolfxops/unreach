"""Public exports; only live_symbol is imported."""


def live_symbol() -> str:
    return "imported"


def dead_symbol() -> str:
    return "never imported"
