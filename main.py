"""Digate entrypoint."""

from __future__ import annotations

from digate.api import create_app
from digate.demo import print_demo, run_demo

app = create_app()


def demo() -> None:
    print_demo()


if __name__ == "__main__":
    demo()
