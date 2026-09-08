"""Imported as a module; attribute access hides which names are live."""


def on_event() -> str:
    return "called via hooks.on_event"


def maybe_dead() -> str:
    return "ambiguous: module imported whole"
