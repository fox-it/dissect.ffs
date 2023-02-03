import datetime
import gzip
import stat
from io import BytesIO
from unittest.mock import call, patch

import pytest

from dissect.ffs.ffs import FFS, INode


def test_ffs(ffs_bin):
    ffs = FFS(ffs_bin)

    assert ffs.version == 2

    root = ffs.root
    assert root.type == stat.S_IFDIR
    assert root.is_dir()
    assert root.atime == datetime.datetime(2022, 4, 22, 14, 15, 14, tzinfo=datetime.timezone.utc)
    assert root.atime_ns == 1650636914000000000
    assert list(root.listdir().keys()) == [".", "..", ".snap", "test_file", "test_dir"]

    test_file = ffs.get("test_file")
    assert test_file.open().read() == b"test contents\n"


@pytest.mark.parametrize(
    "image_file",
    [
        ("tests/data/ffs_symlink_test1.bin.gz"),
        ("tests/data/ffs_symlink_test2.bin.gz"),
        ("tests/data/ffs_symlink_test3.bin.gz"),
    ],
)
def test_symlinks(image_file):
    path = "/path/to/dir/with/file.ext"
    expect = b"resolved!\n"

    def resolve(node):
        while node.type == stat.S_IFLNK:
            node = node.link_inode
        return node

    with gzip.open(image_file, "rb") as disk:
        assert resolve(FFS(disk).get(path)).open().read() == expect


@patch("dissect.ffs.ffs.INode.open", return_value=BytesIO(b"\x00" * 16))
@patch("dissect.ffs.ffs.log", create=True, return_value=None)
@patch("dissect.ffs.ffs.FFS")
def test_infinite_loop_protection(FFS, log, *args):
    inode = INode(FFS, 1, filetype=stat.S_IFDIR)
    inode.size = 16
    for _ in inode.iterdir():
        pass
    assert call.critical("Zero-length directory entry in %s (offset 0x%x)", inode, 0) in log.mock_calls
