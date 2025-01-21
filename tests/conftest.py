from __future__ import annotations

import gzip
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator


def absolute_path(filename: str) -> Path:
    return Path(__file__).parent / filename


def gzip_file(filename: str) -> Iterator[BinaryIO]:
    with gzip.GzipFile(absolute_path(filename), "rb") as fh:
        yield fh


@pytest.fixture
def ffs_bin() -> Iterator[BinaryIO]:
    yield from gzip_file("data/ffs.bin.gz")
