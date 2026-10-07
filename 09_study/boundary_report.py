#!/usr/bin/env python3
"""boundary_report.py — where do raters disagree, and is the scale soft there?

  python3 boundary_report.py labels_zane_day1.csv labels_rater_b.csv [labels_scorer.csv] [--key answer_key...json]

For every pair of sheets: exact and within-one agreement, and the disagreements grouped by the level BOUNDARY they
straddle (0-1, 1-2, 2-3, 3-4, 4-5) with direction (which sheet read higher). With three or more sheets the human
median is formed from the sheets whose names do not contain 'scorer', and the scorer sheet is compared to it: the
share of items within one notch of the human median is the "internal use" acceptance number (>= 80% proposed).
Asserts nothing; prints a report a person can read."""
import csv, itertools, json, statistics, sys
from collections import Counter

def read(p):
    return {r["id"]: int(r["level_0_to_5"]) for r in csv.DictReader(open(p)) if r.get("level_0_to_5", "").strip() != ""}

def pair(a, b, na, nb):
    ids = sorted(set(a) & set(b)); ex = sum(a[i] == b[i] for i in ids); w1 = sum(abs(a[i] - b[i]) <= 1 for i in ids)
    bounds = Counter(); direction = Counter(); big = []
    for i in ids:
        if a[i] == b[i]: continue
        lo, hi = sorted((a[i], b[i]))
        for k in range(lo, hi): bounds[f"{k}-{k+1}"] += 1
        direction[na if a[i] > b[i] else nb] += 1
        if hi - lo >= 2: big.append((i, a[i], b[i]))
    print(f"\n{na} vs {nb}: n={len(ids)} exact {ex/len(ids):.0%} within-one {w1/len(ids):.0%}")
    print("  disagreements straddle:", ", ".join(f"{k}: {v}" for k, v in sorted(bounds.items())) or "none")
    print("  read higher:", dict(direction) or "-", "| two or more apart:", big or "none")

def main():
    argv = sys.argv[1:]; key = None
    if "--key" in argv:
        k = argv.index("--key"); key = {kk: v["intended_level"] for kk, v in json.load(open(argv[k + 1])).items()}; argv = argv[:k] + argv[k + 2:]
    args = [a for a in argv if not a.startswith("--")]
    sheets = {p: read(p) for p in args}
    for (pa, a), (pb, b) in itertools.combinations(sheets.items(), 2): pair(a, b, pa, pb)
    humans = {p: s for p, s in sheets.items() if "scorer" not in p}; scorers = {p: s for p, s in sheets.items() if "scorer" in p}
    if len(humans) >= 2:
        ids = sorted(set.intersection(*[set(s) for s in humans.values()]))
        med = {i: statistics.median_low([s[i] for s in humans.values()]) for i in ids}
        per_level = Counter(med.values()); soft = Counter()
        for i in ids:
            vals = [s[i] for s in humans.values()]
            if max(vals) != min(vals): soft[med[i]] += 1
        print(f"\nhuman median (n={len(humans)} raters, {len(ids)} items): items per level {dict(sorted(per_level.items()))}")
        print("  share of items where humans disagree, by median level:", {k: f"{soft[k]}/{per_level[k]}" for k in sorted(per_level)})
        for ps, s in scorers.items():
            ok1 = sum(abs(s[i] - med[i]) <= 1 for i in ids if i in s); ex = sum(s[i] == med[i] for i in ids if i in s); n = sum(1 for i in ids if i in s)
            print(f"  {ps} vs human median: exact {ex/n:.0%}, within-one {ok1/n:.0%}  -> {'meets' if ok1/n >= .8 else 'below'} the 80% internal-use bar")
            pair(s, med, ps, "human-median")
    if key:
        for p, s in sheets.items():
            ids = [i for i in s if i in key]; print(f"\n{p} vs sealed key: exact {sum(s[i]==key[i] for i in ids)/len(ids):.0%} within-one {sum(abs(s[i]-key[i])<=1 for i in ids)/len(ids):.0%}")

if __name__ == "__main__": main()
