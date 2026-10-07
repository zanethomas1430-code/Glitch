#!/usr/bin/env python3
"""kappa.py — agreement on the 0-5 specificity scale.

  python3 kappa.py labels_A.csv labels_B.csv [labels_C.csv ...]      # humans vs humans
  python3 kappa.py labels_A.csv labels_B.csv --key answer_key.DO_NOT_OPEN_UNTIL_LABELED.json   # + vs intended
  python3 kappa.py --self labels_A_day1.csv labels_A_day14.csv     # one person, two sittings (consistency, NOT kappa)

Reports Cohen's kappa (pairwise), Fleiss' kappa (all raters), quadratic-weighted kappa (near misses count less),
exact and within-one agreement, and where disagreements cluster by level and by framing axis. Asserts nothing;
prints what the numbers are and what they are conventionally read as.
"""
import csv, itertools, json, sys
from collections import Counter, defaultdict

LEVELS = list(range(6))

def read(path):
    out = {}
    for row in csv.DictReader(open(path)):
        v = row.get("level_0_to_5", "").strip()
        if v == "": continue
        out[row["id"]] = int(v)
    return out

def cohen(a, b, weighted=False):
    ids = sorted(set(a) & set(b)); n = len(ids)
    if n == 0: return None, 0
    obs = Counter((a[i], b[i]) for i in ids)
    pa = Counter(a[i] for i in ids); pb = Counter(b[i] for i in ids)
    if weighted:
        w = lambda i, j: ((i - j) ** 2) / 25.0
        po = sum(w(i, j) * obs[(i, j)] for i in LEVELS for j in LEVELS) / n
        pe = sum(w(i, j) * pa[i] * pb[j] for i in LEVELS for j in LEVELS) / (n * n)
        return (1 - po / pe) if pe else None, n
    po = sum(obs[(i, i)] for i in LEVELS) / n
    pe = sum(pa[i] * pb[i] for i in LEVELS) / (n * n)
    return ((po - pe) / (1 - pe)) if pe < 1 else None, n

def fleiss(raters):
    ids = sorted(set.intersection(*(set(r) for r in raters))); N = len(ids); k = len(raters)
    if N == 0 or k < 2: return None, N
    P_i = []; pj = Counter()
    for i in ids:
        c = Counter(r[i] for r in raters)
        for lvl, cnt in c.items(): pj[lvl] += cnt
        P_i.append((sum(cnt * cnt for cnt in c.values()) - k) / (k * (k - 1)))
    Pbar = sum(P_i) / N; pj = {l: v / (N * k) for l, v in pj.items()}; Pe = sum(v * v for v in pj.values())
    return ((Pbar - Pe) / (1 - Pe)) if Pe < 1 else None, N

def read_as(k):
    if k is None: return "undefined"
    return ("poor" if k < .2 else "fair" if k < .4 else "moderate" if k < .6 else "substantial" if k < .8 else "almost perfect")

def main():
    args = sys.argv[1:]; key = None; self_mode = "--self" in args
    if "--key" in args: key = json.load(open(args[args.index("--key") + 1])); args = [a for i, a in enumerate(args) if a != "--key" and (i == 0 or args[i - 1] != "--key")]
    paths = [a for a in args if not a.startswith("--")]
    raters = [read(p) for p in paths]
    if self_mode:
        a, b = raters[0], raters[1]; ids = sorted(set(a) & set(b))
        exact = sum(a[i] == b[i] for i in ids) / len(ids); w1 = sum(abs(a[i] - b[i]) <= 1 for i in ids) / len(ids)
        print(f"self-consistency over {len(ids)} items: exact {exact:.0%}, within one level {w1:.0%}")
        print("This is ONE person's stability across time. It is not inter-rater agreement and cannot stand in for it.")
        return
    print(f"raters: {len(raters)} | items labeled by all: {len(set.intersection(*(set(r) for r in raters)))}")
    for (i, a), (j, b) in itertools.combinations(enumerate(raters), 2):
        k, n = cohen(a, b); kw, _ = cohen(a, b, weighted=True); ids = sorted(set(a) & set(b))
        exact = sum(a[x] == b[x] for x in ids) / n; w1 = sum(abs(a[x] - b[x]) <= 1 for x in ids) / n
        print(f"  {paths[i]} vs {paths[j]}: kappa {k:.2f} ({read_as(k)}), weighted {kw:.2f}, exact {exact:.0%}, within-one {w1:.0%}")
    if len(raters) >= 3:
        f, N = fleiss(raters); print(f"  Fleiss kappa (all {len(raters)}): {f:.2f} ({read_as(f)})")
    # where do they disagree?
    ids = sorted(set.intersection(*(set(r) for r in raters)))
    spread = {i: max(r[i] for r in raters) - min(r[i] for r in raters) for i in ids}
    by_level = defaultdict(list)
    for i in ids: by_level[round(sum(r[i] for r in raters) / len(raters))].append(spread[i])
    print("\nspread (max-min across raters) by consensus level:")
    for lvl in LEVELS:
        if by_level[lvl]: print(f"  level {lvl}: n={len(by_level[lvl])} mean spread {sum(by_level[lvl])/len(by_level[lvl]):.2f}")
    if key:
        print("\nvs intended level (from the sealed key):")
        for p, r in zip(paths, raters):
            hit = sum(r[i] == key[i]["intended_level"] for i in r if i in key) / len(r)
            w1 = sum(abs(r[i] - key[i]["intended_level"]) <= 1 for i in r if i in key) / len(r)
            print(f"  {p}: exact {hit:.0%}, within-one {w1:.0%}")
        by_axis = defaultdict(list)
        for i in ids:
            cons = round(sum(r[i] for r in raters) / len(raters)); by_axis[key[i]["axis"]].append(abs(cons - key[i]["intended_level"]))
        print("\nconsensus error by framing axis (the invariance question):")
        for ax, errs in sorted(by_axis.items(), key=lambda x: -sum(x[1]) / len(x[1])):
            print(f"  {ax:>13}: n={len(errs)} mean |consensus - intended| {sum(errs)/len(errs):.2f}")
        worst = sorted(ids, key=lambda i: -spread[i])[:5]
        print("\nfive most contested items (open these together):", ", ".join(f"{i}(spread {spread[i]})" for i in worst))
    print("\nA weighted kappa under 0.6 means the scale needs work before any detector built on it means anything.")

if __name__ == "__main__": main()
