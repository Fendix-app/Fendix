"""A-D5 evidence-storage measurement harness (PHASE1-GATE-PROPOSALS 1.4b, gate G2.10).

Measures, for one engine binary, the engine's peak RSS, wall time and report
bytes on the worst case the bounded-storage design must survive: a synthetic
target scanned with `--max-endpoints 0` (no endpoint cap), where every
discovered endpoint answers 403, so every endpoint is one unevaluated group
(endpoint, origin=target, reason=gated). One extra endpoint answers 200 so the
pass is not a total loss.

The design parameters are recorded with each result: G_inline (inline groups),
P (groups per page) and H (listing ceiling). A post-contract engine is expected
to honour them; a pre-contract engine ignores them, and the harness records
what it actually wrote (groups_total, inline group count, ceiling flag), so the
same harness gives the before and after numbers.

Usage (stdlib only; run with `python3 -I`):

  python3 -I measure.py --binary /path/to/fendix --endpoints 50 500 2000 \
      --out /tmp/d5 [--g-inline 200 --page 1000 --ceiling 100000] [--max-duration 600s]

Reaching H = 100,000 groups needs 100,000 endpoints and several hundred
thousand probe requests on loopback: run that size only under the heavy-work
rules (disk check, the .heavy.lock), never in CI.

Output: one JSON object per size on stdout and in <out>/results.jsonl.

RSS assertion (OR-13, risk R-34), runnable small:

  python3 -I measure.py --binary <fendix> --endpoints 10 150 --out /tmp/d5 \
      --max-rss-bytes-per-probe 1024

compares the smallest and largest sizes and exits 1 when peak RSS grows by more
than that many bytes per additional attempted probe. Probe storage that is
bounded independently of the probe count leaves only per-endpoint state, which
is a small fraction of the ~22 probes each endpoint gets. `--max-rss-mb` adds an
absolute ceiling on every run.
"""

import argparse
import http.server
import json
import os
import platform
import re
import subprocess
import sys
import threading
import time
from pathlib import Path


def make_handler(n_endpoints):
    links = "".join('<a href="/e/%06d?id=1">e</a>\n' % i for i in range(n_endpoints))
    index = ('<html><body><a href="/open?q=1">open</a>\n' + links + "</body></html>").encode()
    locs = "".join("<url><loc>http://HOST/e/%06d?id=1</loc></url>" % i for i in range(n_endpoints))

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, code, body, ctype="text/plain"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _route(self):
            path = self.path.split("?", 1)[0]
            if path == "/":
                return self._send(200, index, "text/html")
            if path == "/sitemap.xml":
                host = self.headers.get("Host", "127.0.0.1")
                body = ('<?xml version="1.0"?><urlset>' + locs.replace("HOST", host) + "</urlset>").encode()
                return self._send(200, body, "application/xml")
            if path == "/robots.txt":
                return self._send(200, b"User-agent: *\nAllow: /\n")
            if path == "/open":
                return self._send(200, b"ok", "text/html")
            return self._send(403, b"forbidden")

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _route

        def log_message(self, *args):
            pass

    return Handler


def peak_rss_bytes(time_stderr):
    # macOS /usr/bin/time -l: "<n>  maximum resident set size" (bytes).
    m = re.search(r"(\d+)\s+maximum resident set size", time_stderr)
    if m:
        return int(m.group(1))
    # GNU time -v: "Maximum resident set size (kbytes): <n>".
    m = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", time_stderr)
    if m:
        return int(m.group(1)) * 1024
    return None


class QuietServer(http.server.ThreadingHTTPServer):
    # The stdlib default backlog (5) drops connections under the probe load,
    # which the engine then records as unknown-origin probes: noise in a run
    # meant to be all 403.
    request_queue_size = 4096
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


def run_one(args, n):
    server = QuietServer(("127.0.0.1", 0), make_handler(n))
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    outdir = Path(args.out) / ("n%d" % n)
    outdir.mkdir(parents=True, exist_ok=True)
    report = outdir / "report.json"
    time_flag = "-l" if platform.system() == "Darwin" else "-v"
    # The engine's own stderr goes to a file (the hosted worker holds all of it
    # in memory: OR-28); `exec` keeps the measured process the engine itself.
    stderr_file = outdir / "engine.stderr"
    cmd = ["/usr/bin/time", time_flag, "/bin/sh", "-c", 'exec "$0" "$@" 2>"$FENDIX_HARNESS_STDERR"', args.binary, "scan",
           "--url", "http://127.0.0.1:%d/" % port,
           "--enable-active", "--max-endpoints", "0",
           "--max-duration", args.max_duration,
           "--format", "json", "-o", str(report)]
    env = dict(os.environ,
               FENDIX_PROBE_INLINE_GROUPS=str(args.g_inline),
               FENDIX_PROBE_PAGE_GROUPS=str(args.page),
               FENDIX_PROBE_LISTING_CEILING=str(args.ceiling),
               FENDIX_HARNESS_STDERR=str(stderr_file))
    t0 = time.monotonic()
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    wall = time.monotonic() - t0
    server.shutdown()

    files = {p.name: p.stat().st_size for p in outdir.iterdir() if p.is_file() and p.name != "engine.stderr"}
    stderr_bytes = stderr_file.stat().st_size if stderr_file.exists() else None
    result = {
        "endpoints": n,
        "g_inline": args.g_inline, "page": args.page, "ceiling": args.ceiling,
        "exit": proc.returncode,
        "wall_s": round(wall, 2),
        "peak_rss_bytes": peak_rss_bytes(proc.stderr),
        "report_bytes": files.get("report.json"),
        "engine_stderr_bytes": stderr_bytes,
        "output_files": files,
    }
    if report.exists():
        doc = json.loads(report.read_text(encoding="utf-8"))
        meta = doc.get("metadata", {})
        ap = (meta.get("coverage") or {}).get("active_probes") or {}
        status = {s["name"]: s["state"] for s in meta.get("scanner_status", [])}
        result.update({
            # Every path the crawler guesses also answers 403, so the number of
            # gated groups is close to endpoints_scanned, not to --endpoints.
            "endpoints_scanned": meta.get("endpoints_scanned"),
            "unknown_origin": ap.get("unknown_origin"),
            "scanner_failed": ap.get("scanner_failed"),
            "active_probes_state": status.get("active-probes"),
            "configured_complete": (meta.get("coverage") or {}).get("configured_complete"),
            "attempted": ap.get("attempted"),
            "evaluated": ap.get("evaluated"),
            "gated": (ap.get("gated") or {}).get("total"),
            "active_probes_json_bytes": len(json.dumps(ap, separators=(",", ":"))),
            "not_evaluated_checks": len(ap.get("not_evaluated_checks") or []),
            "groups_total": ap.get("groups_total"),
            "inline_groups": len(ap.get("not_evaluated_groups") or []) if "not_evaluated_groups" in ap else None,
            "inline_truncated": ap.get("inline_truncated"),
            "listing_ceiling_reached": ap.get("listing_ceiling_reached"),
            "listing_overflow": ap.get("listing_overflow"),
            "findings": len(doc.get("findings") or []),
        })
    else:
        result["stderr_tail"] = proc.stderr[-2000:]
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--endpoints", type=int, nargs="+", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--g-inline", type=int, default=200)
    ap.add_argument("--page", type=int, default=1000)
    ap.add_argument("--ceiling", type=int, default=100000)
    ap.add_argument("--max-duration", default="600s")
    ap.add_argument("--max-rss-bytes-per-probe", type=float, default=None,
                    help="fail when peak RSS grows faster than this between the smallest and largest size")
    ap.add_argument("--max-rss-mb", type=float, default=None, help="fail when any run's peak RSS exceeds this")
    ap.add_argument("--max-stderr-kb", type=float, default=None, help="fail when any run's engine stderr exceeds this (OR-28: 1024)")
    args = ap.parse_args()
    Path(args.out).mkdir(parents=True, exist_ok=True)
    results = []
    with open(Path(args.out) / "results.jsonl", "a", encoding="utf-8") as fh:
        for n in args.endpoints:
            r = run_one(args, n)
            results.append(r)
            line = json.dumps(r, sort_keys=True)
            print(line, flush=True)
            fh.write(line + "\n")
    return check_rss(args, results)


def check_rss(args, results):
    failed = False
    if args.max_rss_mb is not None:
        for r in results:
            rss = r.get("peak_rss_bytes")
            if rss is None or rss > args.max_rss_mb * 2**20:
                print("RSS FAIL: %d endpoints peaked at %s bytes, ceiling %.0f MiB" % (r["endpoints"], rss, args.max_rss_mb))
                failed = True
    if getattr(args, "max_stderr_kb", None) is not None:
        for r in results:
            n = r.get("engine_stderr_bytes")
            if n is None or n > args.max_stderr_kb * 1024:
                print("STDERR FAIL: %d endpoints wrote %s bytes of engine stderr, limit %.0f KiB" % (r["endpoints"], n, args.max_stderr_kb))
                failed = True
    if args.max_rss_bytes_per_probe is not None:
        ok = [r for r in results if r.get("peak_rss_bytes") and r.get("attempted")]
        if len(ok) < 2:
            print("RSS FAIL: the slope needs two sizes with a report and an RSS reading")
            return 1
        lo, hi = min(ok, key=lambda r: r["attempted"]), max(ok, key=lambda r: r["attempted"])
        extra = hi["attempted"] - lo["attempted"]
        if extra <= 0:
            print("RSS FAIL: the sizes did not differ in attempted probes")
            return 1
        slope = (hi["peak_rss_bytes"] - lo["peak_rss_bytes"]) / extra
        verdict = "PASS" if slope <= args.max_rss_bytes_per_probe else "FAIL"
        print("RSS %s: %.0f bytes of peak RSS per additional probe (%d -> %d probes, %d -> %d bytes), limit %.0f"
              % (verdict, slope, lo["attempted"], hi["attempted"], lo["peak_rss_bytes"], hi["peak_rss_bytes"], args.max_rss_bytes_per_probe))
        failed = failed or verdict == "FAIL"
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
