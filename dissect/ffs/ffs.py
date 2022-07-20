import io
import stat
from functools import cached_property, lru_cache

from dissect.util import ts
from dissect.util.stream import RunlistStream

from dissect.ffs.c_ffs import c_ffs
from dissect.ffs.exceptions import (
    Error,
    NotADirectoryError,
    FileNotFoundError,
    NotASymlinkError,
)


DEV_BSIZE = 512
SBLOCKSEARCH = [
    c_ffs.SBLOCK_UFS2,
    c_ffs.SBLOCK_UFS1,
    c_ffs.SBLOCK_FLOPPY,
    c_ffs.SBLOCK_PIGGY,
]


class FFS:
    def __init__(self, fh):
        self.fh = fh

        self.sb = None
        for sb_offset in SBLOCKSEARCH:
            sb = FFS.read_sb(fh, sb_offset)
            if sb is not None:
                self.sb = sb
                break
        else:
            raise Error("Can't find FFS superblock")

        if self.sb.fs_magic == c_ffs.FS_UFS1_MAGIC:
            self.version = 1
            self._inode_type = c_ffs.ufs1_dinode
            self._addr_type = c_ffs.ufs1_daddr_t
        else:
            self.version = 2
            self._inode_type = c_ffs.ufs2_dinode
            self._addr_type = c_ffs.ufs2_daddr_t

        self.block_size = self.sb.fs_bsize
        self.fragment_size = self.sb.fs_fsize
        self.inode_size = self.sb.fs_bsize // self.sb.fs_inopb

        self.mount_name = bytes(self.sb.fs_fsmnt).split(b"\x00")[0].decode("utf-8")
        self.volume_name = bytes(self.sb.fs_volname).split(b"\x00")[0].decode("utf-8")

        self.root = self.inode(c_ffs.UFS_ROOTINO, "/")

    @staticmethod
    def read_sb(fh, offset):
        fh.seek(offset)
        try:
            sb = c_ffs.fs(fh)
        except Exception:
            return None

        if sb.fs_magic not in (c_ffs.FS_UFS1_MAGIC, c_ffs.FS_UFS2_MAGIC):
            return None

        if sb.fs_ncg < 1 or not (c_ffs.MINBSIZE <= sb.fs_bsize <= c_ffs.MAXBSIZE) or sb.fs_sbsize > c_ffs.SBLOCKSIZE:
            return None

        return sb

    @lru_cache(1024)
    def cylinder_group(self, num):
        return CylinderGroup(self, num)

    def cylinder_groups(self):
        for num in range(self.sb.fs_ncg):
            yield self.cylinder_group(num)

    @lru_cache(4096)
    def inode(self, inum, name=None, filetype=None):
        return INode(self, inum, name, filetype)

    def get(self, path, node=None):
        if isinstance(path, int):
            return self.inode(path)

        node = node or self.root

        parts = path.split("/")
        for i, p in enumerate(parts):
            if not p:
                continue

            for child in node.iterdir():
                if child.name == p:
                    node = child
                    break
            else:
                raise FileNotFoundError(f"File not found: {path}")

        return node

    def iter_inodes(self):
        cur_cg = None
        cur_cgnum = None

        num_inodes = self.sb.fs_ncg * self.sb.fs_ipg  # number of groups * inodes per group
        for inum in range(c_ffs.UFS_ROOTINO, num_inodes):
            cgnum = ino_to_cg(self, inum)
            if cgnum != cur_cgnum:
                cur_cg = self.cylinder_group(cgnum)
                cur_cgnum = cgnum

            if cur_cg.inode_allocated(inum):
                yield self.inode(inum)


class CylinderGroup:
    def __init__(self, fs, num):
        self.fs = fs
        self.num = num

        self.block = fsbtodb(fs, cgtod(fs, num))
        self.offset = self.block * DEV_BSIZE

        fs.fh.seek(self.offset)
        self.cg = c_ffs.cg(fs.fh)
        if self.cg.cg_magic != c_ffs.CG_MAGIC:
            raise Error("Invalid cylinder group magic")

    def inode_allocated(self, inum):
        rel_inum = inum % self.fs.sb.fs_ipg

        byte_offset, bit_offset = divmod(rel_inum, 8)
        offset = self.offset + self.cg.cg_iusedoff + byte_offset

        self.fs.fh.seek(offset)
        bitmap = self.fs.fh.read(1)[0]

        return bitmap & (1 << bit_offset) != 0


class INode:
    def __init__(self, fs, inum, name=None, filetype=None):
        self.fs = fs
        self.inum = inum
        self.name = name
        self._type = filetype

        self._runlist = None

    def __repr__(self):
        return f"<inode {self.inum:d}>"

    def _read_inode(self):
        block = fsbtodb(self.fs, ino_to_fsba(self.fs, self.inum))
        offset = (block * DEV_BSIZE) + (ino_to_fsbo(self.fs, self.inum) * self.fs.inode_size)
        self.fs.fh.seek(offset)
        return self.fs._inode_type(self.fs.fh)

    @cached_property
    def cg(self):
        return self.fs.cylinder_group(ino_to_cg(self.fs, self.inum))

    @cached_property
    def inode(self):
        return self._read_inode()

    @cached_property
    def size(self):
        return self.inode.di_size

    @cached_property
    def type(self):
        return self._type or stat.S_IFMT(self.inode.di_mode)

    @cached_property
    def mode(self):
        return self.inode.di_mode

    @cached_property
    def atime(self):
        return ts.from_unix_ns(self.atime_ns)

    @cached_property
    def atime_ns(self):
        return (self.inode.di_atime * 1000000000) + self.inode.di_atimensec

    @cached_property
    def mtime(self):
        return ts.from_unix_ns(self.mtime_ns)

    @cached_property
    def mtime_ns(self):
        return (self.inode.di_mtime * 1000000000) + self.inode.di_mtimensec

    @cached_property
    def ctime(self):
        return ts.from_unix_ns(self.ctime_ns)

    @cached_property
    def ctime_ns(self):
        return (self.inode.di_ctime * 1000000000) + self.inode.di_ctimensec

    @cached_property
    def btime(self):
        return ts.from_unix_ns(self.btime_ns)

    @cached_property
    def btime_ns(self):
        return (self.inode.di_birthtime * 1000000000) + self.inode.di_birthnsec

    @cached_property
    def link(self):
        if not self.is_symlink():
            raise NotASymlinkError(f"{self!r} is not a symlink")

        return self.open().read().decode("utf-8")

    def is_dir(self):
        return self.type == stat.S_IFDIR

    def is_file(self):
        return self.type == stat.S_IFREG

    def is_symlink(self):
        return self.type == stat.S_IFLNK

    def listdir(self):
        return {node.name: node for node in self.iterdir()}

    def iterdir(self):
        if not self.is_dir():
            raise NotADirectoryError(f"{self!r} is not a directory")

        buf = self.open()
        offset = 0

        while offset < self.size - 8:
            dirent = c_ffs.direct(buf)
            dname = buf.read(dirent.d_namlen).decode("utf-8", "surrogateescape")
            dtype = dirent.d_type << 12

            yield self.fs.inode(dirent.d_ino, dname, dtype)

            # Can find slack entries if d_reclen > d_namlen (rounded to nearest 4 bytes)
            offset += dirent.d_reclen
            buf.seek(offset)

    def dataruns(self):
        # So this is a bit confusing.
        # FFS uses file system blocks for logical addressing (e.g. 32k).
        # File system blocks are made up of fragments (e.g. 4k).
        # Within source code, you generally only see references to file system blocks.
        # However, all block numbers are actually fragment numbers. File system blocks
        # just happen to be in steps of however-many-fragments-are-in-a-file-system-block.
        # E.g. the file system blocks 993776 and 993784 are actually contigious, because
        # there are 8 fragments in a file system block.
        # Because of this, we do a bit of run number manipulation to create an efficient run list.
        # To be safe, we also use the fragment size as block size for the RunlistStream.
        if not self._runlist:
            runs = []
            run_offset = None
            run_size = 1
            for block_num in self._iter_blocks():
                if run_offset is None:
                    run_offset = block_num
                    continue

                if block_num == run_offset + (run_size * self.fs.sb.fs_frag):
                    run_size += 1
                else:
                    run_size *= self.fs.sb.fs_frag
                    if run_offset == 0:
                        runs.append((None, run_size))
                    else:
                        runs.append((run_offset, run_size))

                    run_offset = block_num
                    run_size = 1

            runs.append((run_offset, run_size * self.fs.sb.fs_frag))

            self._runlist = runs

        return self._runlist

    def open(self):
        if self.is_symlink() and self.size < self.fs.sb.fs_maxsymlinklen:
            # This is a bit hacky since we prefer to parse di_db and di_ib as arrays, rather than bytes
            # However, short symlinks store the link here
            buf = io.BytesIO()
            self.fs._addr_type[c_ffs.UFS_NDADDR].write(buf, self.inode.di_db)
            self.fs._addr_type[c_ffs.UFS_NIADDR].write(buf, self.inode.di_ib)
            buf.seek(0)
            # Need to add a size attribute to maintain compatibility with dissect streams
            buf.size = self.size
            return buf

        return RunlistStream(self.fs.fh, self.dataruns(), self.size, self.fs.fragment_size)

    def _iter_blocks(self):
        num_blocks = (self.size + self.fs.block_size - 1) // self.fs.block_size
        num_direct_blocks = min(num_blocks, c_ffs.UFS_NDADDR)

        blocks = self.inode.di_db[:num_direct_blocks]
        num_blocks -= num_direct_blocks

        yield from blocks

        if num_blocks > 0:
            for level in range(1, c_ffs.UFS_NIADDR):
                indirect_block = self.inode.di_ib[level - 1]
                for block, level in self._walk_indirect(indirect_block, level, num_blocks):
                    if level != 0:
                        continue

                    yield block
                    num_blocks -= 1

    def _walk_indirect(self, block, level, num_blocks):
        yield block, level

        if level > 0:
            addresses_per_block = self.fs.sb.fs_nindir
            max_level_blocks = addresses_per_block**level
            blocks_per_nest = max_level_blocks // addresses_per_block
            read_blocks = (num_blocks + blocks_per_nest - 1) // blocks_per_nest
            read_blocks = min(read_blocks, addresses_per_block)

            self.fs.fh.seek(fsbtodb(self.fs, block) * DEV_BSIZE)
            for addr in self.fs._addr_type[read_blocks](self.fs.fh):
                yield from self._walk_indirect(addr, level - 1, num_blocks)


# Some useful C macros used by UFS/FFS converted to Python functions
# The names are kept to ease debugging/readability when comparing to the original source.
def fsbtodb(fs, b):
    return b << fs.sb.fs_fsbtodb


def dbtofsb(fs, b):
    return b >> fs.sb.fs_fsbtodb


def cgbase(fs, c):
    return fs.sb.fs_fpg * c


def cgdata(fs, c):
    return cgdmin(fs, c) + fs.sb.fs_metaspace


def cgmeta(fs, c):
    return cgdmin(fs, c)


def cgdmin(fs, c):
    return cgstart(fs, c) + fs.sb.fs_dblkno


def cgimin(fs, c):
    return cgstart(fs, c) + fs.sb.fs_iblkno


def cgsblock(fs, c):
    return cgstart(fs, c) + fs.sb.fs_sblkno


def cgtod(fs, c):
    return cgstart(fs, c) + fs.sb.fs_cblkno


def cgstart(fs, c):
    if fs.sb.fs_magic == c_ffs.FS_UFS2_MAGIC:
        return cgbase(fs, c)
    else:
        return cgbase(fs, c) + fs.sb.fs_old_cgoffset * (c & ~fs.sb.fs_old_cgmask)


def ino_to_cg(fs, x):
    # inode number to cylinder group number.
    return x // fs.sb.fs_ipg


def ino_to_fsba(fs, x):
    # inode number to filesystem block address.
    return cgimin(fs, ino_to_cg(fs, x)) + blkstofrags(fs, (x % fs.sb.fs_ipg) // fs.sb.fs_inopb)


def ino_to_fsbo(fs, x):
    # inode number to filesystem block offset.
    return x % fs.sb.fs_inopb


def blkstofrags(fs, blks):
    return blks << fs.sb.fs_fragshift
