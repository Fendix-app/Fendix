import os

REPORTS_DIR = "/srv/app/reports"


def load_report(filename: str) -> str:
    with open(os.path.join(REPORTS_DIR, filename), encoding="utf-8") as fh:  # EVAL-SINK
        return fh.read()
