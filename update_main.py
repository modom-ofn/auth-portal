from pathlib import Path

path = Path("main.go")
path.write_bytes(path.read_bytes().replace(b"\xe2\x80\x8b", b""))
