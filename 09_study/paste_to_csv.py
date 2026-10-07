#!/usr/bin/env python3
"""paste_to_csv.py — turn a pasted '50QT v1' answer block (from the shared rating page's Copy button) into labels_<name>.csv.

  python3 paste_to_csv.py pasted.txt          # or:  pbpaste | python3 paste_to_csv.py -
Writes labels_<name>.csv next to responses.jsonl in the shape kappa.py reads. A trailing '?' on a level means unsure."""
import json, re, sys
from pathlib import Path
src = sys.stdin.read() if len(sys.argv) < 2 or sys.argv[1] == "-" else Path(sys.argv[1]).read_text()
m = re.search(r"50QT v1 name=(\S+)", src)
if not m: sys.exit("no '50QT v1 name=…' header found in the pasted text")
name = re.sub(r"[^a-z0-9]+", "_", m.group(1).lower())
pairs = dict((k, v) for k, v in re.findall(r"\b(R\d\d)=([0-5]\??)", src))
here = Path(__file__).resolve().parent
rows = [json.loads(l) for l in open(here / "responses.jsonl")]
missing = [r["id"] for r in rows if r["id"] not in pairs]
if missing: sys.exit(f"missing {len(missing)} items: {missing[:10]}")
out = here / f"labels_{name}.csv"
with open(out, "w") as f:
    f.write("id,response,level_0_to_5,confident_yes_no,notes\n")
    for r in rows:
        v = pairs[r["id"]]; lvl = v.rstrip("?"); unsure = v.endswith("?")
        f.write(f'{r["id"]},"{r["text"].replace(chr(34), chr(34)*2)}",{lvl},{"no" if unsure else "yes"},\n')
print(f"wrote {out} ({len(rows)} rows, {sum(v.endswith('?') for v in pairs.values())} unsure)")
