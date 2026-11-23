#!/usr/bin/env python3
"""Report fixed PostgreSQL fixture failure classes without disclosing log text."""
import collections
import sys


def classify(lines):
    counts = collections.Counter()
    for line in lines:
        # SQL and DETAIL records may contain arbitrary application payloads.
        if any(tag in line for tag in ("STATEMENT:", "DETAIL:", "CONTEXT:")):
            continue
        for marker, reason in (
            ("No space left on device", "storage_exhausted"),
            ("out of memory", "memory_exhausted"),
            ("PANIC:", "server_panic"),
            ("terminated by signal", "process_signaled"),
            ("database system is shut down", "server_shutdown"),
            ("database system was interrupted", "server_interrupted"),
        ):
            if marker in line:
                counts[reason] += 1
    return dict(sorted(counts.items()))


if __name__ == "__main__":
    import json
    print("fixture_database_log_classes=" + json.dumps(classify(sys.stdin), sort_keys=True))
