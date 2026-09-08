"""Entry point. Imports used symbols only."""

from pkg import hooks
from pkg.exports import live_symbol
from pkg.used import helper


def main() -> str:
    return helper() + live_symbol() + hooks.on_event()
