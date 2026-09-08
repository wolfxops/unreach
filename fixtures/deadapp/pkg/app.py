"""Entry point. Imports used symbols only."""

from pkg.exports import live_symbol
from pkg.used import helper


def main() -> str:
    return helper() + live_symbol()
