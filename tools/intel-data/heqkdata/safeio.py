# SPDX-License-Identifier: AGPL-3.0-only
"""Safe handling of untrusted downloaded files.

Rules (HEQK-DATA-GOVERNANCE.md §5):
  * nothing downloaded is executed, imported, unpickled or evaluated: parsers are csv / json / text;
  * archives are extracted only member-by-member into a fresh directory, refusing absolute paths,
    '..', links, devices, and anything over the size / ratio / count caps (zip bombs);
  * decompression streams are capped;
  * lines and CSV fields are length-capped, so one hostile row cannot exhaust memory;
  * executable-looking members are refused outright (no malware samples in this pipeline).
"""
import csv
import gzip
import io
import json
import os
import stat
import zipfile

MAX_MEMBER = 2 << 30          # 2 GiB per extracted member
MAX_TOTAL = 8 << 30           # 8 GiB per archive
MAX_MEMBERS = 50_000
MAX_RATIO = 200               # uncompressed / compressed per member
MAX_LINE = 1 << 20            # 1 MiB per text line
REFUSED_EXT = (".exe", ".dll", ".scr", ".bin", ".elf", ".so", ".dylib", ".msi", ".apk", ".jar", ".ps1", ".bat",
               ".cmd", ".vbs", ".js", ".hta", ".lnk", ".docm", ".xlsm", ".pyc", ".pkl", ".pickle")


class UnsafeContent(Exception):
    pass


def _safe_member_path(dest, name):
    if name.startswith(("/", "\\")) or ":" in name.split("/")[0]:
        raise UnsafeContent(f"absolute member path {name!r}")
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise UnsafeContent(f"path traversal in {name!r}")
    target = os.path.realpath(os.path.join(dest, *parts))
    if not target.startswith(os.path.realpath(dest) + os.sep):
        raise UnsafeContent(f"member escapes destination: {name!r}")
    return target


def extract_zip(path, dest, allow=None):
    """Extract `path` into empty directory `dest`. `allow(name) -> bool` filters members. Returns the list
    of extracted paths. Raises UnsafeContent on anything suspicious (fail closed: nothing partial is kept
    on error by the caller, who extracts into a temp dir)."""
    os.makedirs(dest, exist_ok=True)
    if os.listdir(dest):
        raise UnsafeContent(f"extraction directory not empty: {dest}")
    out, total = [], 0
    with zipfile.ZipFile(path) as z:
        infos = z.infolist()
        if len(infos) > MAX_MEMBERS:
            raise UnsafeContent(f"{len(infos)} members > {MAX_MEMBERS}")
        for info in infos:
            name = info.filename
            if info.is_dir():
                continue
            mode = (info.external_attr >> 16) & 0o170000
            if mode and mode not in (stat.S_IFREG,):
                raise UnsafeContent(f"non-regular member {name!r} (link/device)")
            if name.lower().endswith(REFUSED_EXT):
                raise UnsafeContent(f"executable-type member {name!r} refused (no samples in this pipeline)")
            if info.flag_bits & 0x1:
                raise UnsafeContent(f"encrypted member {name!r} (password-protected archives are typical of malware sample sets)")
            if allow is not None and not allow(name):
                continue
            if info.file_size > MAX_MEMBER:
                raise UnsafeContent(f"member {name!r} is {info.file_size} bytes > cap")
            if info.compress_size and info.file_size / info.compress_size > MAX_RATIO:
                raise UnsafeContent(f"member {name!r} compression ratio {info.file_size / info.compress_size:.0f} > {MAX_RATIO}")
            total += info.file_size
            if total > MAX_TOTAL:
                raise UnsafeContent("archive total exceeds cap")
            target = _safe_member_path(dest, name)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            written = 0
            with z.open(info) as src, open(target, "xb") as dst:
                while True:
                    chunk = src.read(1 << 20)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > info.file_size or written > MAX_MEMBER:
                        raise UnsafeContent(f"member {name!r} inflates beyond its declared size")
                    dst.write(chunk)
            out.append(target)
    return out


def open_text(path, compression=None, max_bytes=MAX_TOTAL):
    """A text stream over a plain or gzip file with a decompressed-size cap."""
    raw = open(path, "rb")
    if compression == "gzip" or (compression is None and path.endswith(".gz")):
        raw = gzip.GzipFile(fileobj=raw)
    return io.TextIOWrapper(_Capped(raw, max_bytes), encoding="utf-8", errors="replace", newline="")


class _Capped(io.RawIOBase):
    def __init__(self, f, cap):
        self.f, self.cap, self.n = f, cap, 0

    def readable(self):
        return True

    def readinto(self, b):
        data = self.f.read(len(b))
        self.n += len(data)
        if self.n > self.cap:
            raise UnsafeContent(f"decompressed stream exceeds {self.cap} bytes")
        b[:len(data)] = data
        return len(data)

    def close(self):
        self.f.close()
        super().close()


def _bounded(stream, limit=None):
    """Raw lines (newline kept), each read with a size limit: a newline-free hostile file raises after
    `limit` characters instead of being loaded into memory whole (iterating a stream reads to the
    next newline, however far away it is)."""
    limit = MAX_LINE if limit is None else limit
    if not hasattr(stream, "readline"):  # already-materialised lines (a list): check each one
        for n, line in enumerate(stream, 1):
            if len(line) > limit:
                raise UnsafeContent(f"line {n} longer than {limit} bytes")
            yield line
        return
    n = 0
    while True:
        line = stream.readline(limit + 1)
        if not line:
            return
        n += 1
        if len(line) > limit:
            raise UnsafeContent(f"line {n} longer than {limit} bytes")
        yield line


def lines(stream):
    """Yield (line_no, line) with the newline stripped; over-long lines raise before they are read whole."""
    for n, line in enumerate(_bounded(stream), 1):
        yield n, line.rstrip("\r\n")


def csv_rows(stream, **kw):
    csv.field_size_limit(MAX_LINE)
    return csv.reader(_bounded(stream), **kw)


def ndjson(stream, limit=32 << 20):
    """Yield (line_no, object_or_None, reason) for newline-delimited JSON. A line over `limit` bytes is
    skipped (read in bounded pieces, never held whole) and reported with reason, as is a line that is not a
    JSON object; one bad line never stops the file. Non-standard constants (NaN, Infinity) are refused."""
    n = 0
    while True:
        line = stream.readline(limit + 1)
        if not line:
            return
        n += 1
        if len(line) > limit:
            while line and not line.endswith("\n"):
                line = stream.readline(limit + 1)
            yield n, None, f"line longer than {limit} bytes"
            continue
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line, parse_constant=_no_constants)
        except (ValueError, UnsafeContent) as e:
            yield n, None, f"bad JSON: {str(e)[:120]}"
            continue
        if not isinstance(obj, dict):
            yield n, None, "line is not a JSON object"
            continue
        yield n, obj, None


def load_json(path, max_bytes=512 << 20):
    size = os.path.getsize(path)
    if size > max_bytes:
        raise UnsafeContent(f"{path}: {size} bytes > JSON cap {max_bytes}")
    with open(path, "rb") as f:
        return json.loads(f.read().decode("utf-8"), parse_constant=_no_constants)


def _no_constants(name):
    raise UnsafeContent(f"non-standard JSON constant {name}")
