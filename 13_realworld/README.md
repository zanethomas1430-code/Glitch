# 13_realworld: a real log through the historian

Everything before this folder judged logs the testbed wrote itself. `opsat_adapter.py` reads a log the testbed did not write: the Tello scout's flight ledger (`ledger.jsonl`, one row per flight), maps it to historian events without inventing any field, and reports three things: what the historian finds, which of its invariants this log can and cannot support, and which fields would make it provable.

    python3 opsat_adapter.py --ledger ~/Desktop/Tello/flights-mac-keep/ledger.jsonl [--assume-operator-policy] [--out REPORT.md]

Rules the adapter keeps: nothing is invented (a field the ledger lacks is `unrecorded`, and unrecorded is never trusted); every assumption is listed and printed; the adapter's own sequence numbers prove nothing (the ledger has none, so a deleted row is invisible, a LIMIT test); no model text is read.

`REPORT_tello_ledger.md` is the report for the 413-flight ledger (2026-09-12 to 2026-09-23). The raw rows are not in this folder or in the suite zip; the tests use synthetic rows. The Pi's Z-brain ledger (hash-chained) is a different log and is not covered here: it needs access to the Pi.
