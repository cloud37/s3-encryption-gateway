#!/usr/bin/env python3
"""Check or refresh the source-derived gosec suppression inventory (stdlib only)."""

import argparse
from pathlib import Path
import re
import sys

START = "<!-- BEGIN GENERATED GOSEC SUPPRESSIONS -->"
END = "<!-- END GENERATED GOSEC SUPPRESSIONS -->"
DIRECTIVE = re.compile(r"//\s*(?:#nosec|gosec:disable)\s+((?:G\d{3}\s*)+)--\s*(.+)")
GO_TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|`[^`]*`|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/')


def inventory(root):
    rows = []
    for path in sorted(root.rglob("*.go")):
        if ".git" in path.relative_to(root).parts:
            continue
        source = path.read_text()
        for token in GO_TOKEN.finditer(source):
            line = token[0]
            if not line.startswith(("//", "/*")):
                continue
            number = source.count("\n", 0, token.start()) + 1
            if "nolint:" in line and "gosec" in line:
                raise ValueError(f"{path}:{number}: use rule-specific #nosec instead of nolint:gosec")
            if "#nosec" not in line and "gosec:disable" not in line:
                continue
            if line.startswith("/*") or "\n" in line:
                raise ValueError(f"{path}:{number}: use a single-line suppression comment")
            match = DIRECTIVE.fullmatch(line)
            if not match or not match[2].strip() or line.count("#nosec")+line.count("gosec:disable") != 1:
                raise ValueError(f"{path}:{number}: suppression requires rule IDs and -- reason")
            ids = re.findall(r"G\d{3}", match[1])
            if len(ids) != len(set(ids)):
                raise ValueError(f"{path}:{number}: duplicate suppression rule")
            rules = ", ".join(ids)
            reason = match[2].strip().replace("|", "\\|").replace("`", "'")
            tier = "Test fixture" if path.name.endswith("_test.go") or path.relative_to(root).parts[0] == "test" else "Production"
            rows.append(f"| `{path.relative_to(root)}:{number}` | {rules} | {tier} | {reason} |")
    return "\n".join([
        START,
        "| Source location | Rules | Scope | Verified justification / precondition |",
        "|---|---|---|---|",
        *rows,
        END,
    ])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="refresh generated section after reviewing source")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    doc = root / "docs/security/gosec-suppressions.md"
    try:
        generated = inventory(root)
        text = doc.read_text()
        if text.count(START) != 1 or text.count(END) != 1:
            raise ValueError("documentation must contain exactly one generated inventory section")
        before, separator, rest = text.partition(START)
        old, end, after = rest.partition(END)
        if not separator or not end:
            raise ValueError("documentation is missing generated inventory markers")
        expected = before + generated + after
        if args.write:
            doc.write_text(expected)
        elif text != expected:
            raise ValueError("suppression inventory differs from source; review, then run scripts/gosec-suppressions.py --write")
        print("gosec suppression inventory: complete and current")
    except (ValueError, OSError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
