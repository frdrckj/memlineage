"""Copy the memlineage script from a bin wheel into the extension wheel.

Maturin builds a PyO3 wheel and a bin wheel as two artifacts. The extension
wheel is the one we publish. This puts the script into that wheel.
"""

import base64
import hashlib
import stat
import sys
import zipfile
from pathlib import Path


def record_hash(data: bytes) -> str:
    """RECORD hash from PEP 427."""
    digest = hashlib.sha256(data).digest()
    return "sha256=" + base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def script_name(names: list[str]) -> str:
    """The one console script inside a bin wheel."""
    hits = [
        name
        for name in names
        if name.endswith(".data/scripts/memlineage")
        or name.endswith(".data/scripts/memlineage.exe")
    ]
    if len(hits) != 1:
        raise SystemExit(f"expected one memlineage script, found {hits}")
    return hits[0]


def pack(library: Path, binary_wheel: Path) -> None:
    """Add the script to `library` and rewrite RECORD."""
    with zipfile.ZipFile(binary_wheel) as src:
        name = script_name(src.namelist())
        payload = src.read(name)
    tmp = library.with_suffix(".tmp")
    with zipfile.ZipFile(library) as src, zipfile.ZipFile(tmp, "w") as dst:
        record_name = next(item for item in src.namelist() if item.endswith(".dist-info/RECORD"))
        if name in src.namelist():
            raise SystemExit(f"{name} is already in {library.name}")
        lines: list[str] = []
        for info in src.infolist():
            if info.filename == record_name:
                continue
            data = src.read(info.filename)
            dst.writestr(info, data)
            lines.append(f"{info.filename},{record_hash(data)},{len(data)}")
        info = zipfile.ZipInfo(filename=name)
        info.create_system = 3
        info.external_attr = (stat.S_IFREG | 0o755) << 16
        dst.writestr(info, payload)
        lines.append(f"{name},{record_hash(payload)},{len(payload)}")
        lines.append(f"{record_name},,")
        dst.writestr(record_name, "\n".join(lines) + "\n")
    tmp.replace(library)


def main() -> None:
    """Pack one library wheel with the script from one bin wheel."""
    if len(sys.argv) != 3:
        raise SystemExit("usage: pack_cli.py LIBRARY_WHEEL BIN_WHEEL")
    pack(Path(sys.argv[1]), Path(sys.argv[2]))


if __name__ == "__main__":
    main()
