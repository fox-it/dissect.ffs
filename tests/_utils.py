from __future__ import annotations

from pathlib import Path

# TODO: Once the monorepo is fully consolidated, move absolute_path() into dissect.util
#       so all projects can share a single test utility instead of duplicating it.


def absolute_path(filename: str) -> Path:
    return Path(__file__).parent.joinpath(filename).resolve()
