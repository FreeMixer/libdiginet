#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
#
# Every workflow under .github/workflows parses as YAML and names its jobs. GitHub refuses a file
# that does not parse without running a single job, which reads in a pull request as "no checks".
set -u
top=$(cd "$(dirname "$0")/.." && pwd)
python3 -c 'import yaml' 2>/dev/null || { echo "no python3 yaml module: nothing tested"; exit 77; }
ls "$top"/.github/workflows/*.yml >/dev/null 2>&1 || { echo "no workflows (a release tarball): nothing tested"; exit 77; }
python3 - "$top"/.github/workflows/*.yml <<'PY'
import sys, yaml
bad = 0
for path in sys.argv[1:]:
    try:
        doc = yaml.safe_load(open(path))
        jobs = doc.get("jobs") if isinstance(doc, dict) else None
        if not jobs:
            raise ValueError("no jobs")
        print(f"{path.split('/')[-1]}: {len(jobs)} job(s)")
    except Exception as e:
        print(f"FAIL: {path}: {e}")
        bad = 1
sys.exit(bad)
PY
