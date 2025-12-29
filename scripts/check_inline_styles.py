import re
import sys
from pathlib import Path


INLINE_STYLE_RE = re.compile(r"<style\b|style\s*=", re.IGNORECASE)


def check_file(path: Path) -> list[str]:
    hits = []
    try:
        content = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return [f"{path}: failed to read ({exc})"]

    for idx, line in enumerate(content, start=1):
        if INLINE_STYLE_RE.search(line):
            hits.append(f"{path}:{idx}: inline style found")
    return hits


def main() -> int:
    files = [Path(p) for p in sys.argv[1:] if p]
    findings = []
    for path in files:
        if path.suffix.lower() != ".html":
            continue
        findings.extend(check_file(path))

    if findings:
        print("Inline styles are not allowed in templates. Use shared classes in static/styles.css.")
        for hit in findings:
            print(hit)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
