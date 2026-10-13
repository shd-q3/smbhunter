"""Terminal and JSON/CSV output formatting."""

import csv
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone

from smbhunter.tiers import COLORS, RESET, ALL_TIERS

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')


def _sanitise(s):
    """Strip ANSI escapes and control chars from server-supplied strings."""
    return _ANSI_RE.sub('', str(s)).replace('\r', '').replace('\n', ' ')

# ── Colour helpers ─────────────────────────────────────────────────────────

DIM = "\033[2m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
WHITE = "\033[97m"
GREY = "\033[90m"


def supports_color():
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _c(*codes):
    """Return ANSI codes if colour supported, else empty string."""
    return "".join(codes) if supports_color() else ""


def _r():
    return RESET if supports_color() else ""


# ── Size formatting ────────────────────────────────────────────────────────

def human_size(size_bytes):
    if size_bytes is None:
        return "?"
    for unit in ("B", "KB", "MB", "GB"):
        if abs(size_bytes) < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


# ── Print helpers ──────────────────────────────────────────────────────────

def print_host_header(host):
    print(f"\n{_c(BOLD, WHITE)}SMB{_r()}  {_c(BOLD)}{_sanitise(host)}{_r()}", flush=True)


def print_signing(host, required):
    if required:
        print(f"  {_c(GREY)}signing:{_r()} required", flush=True)
    else:
        print(f"  {_c(YELLOW)}signing:{_r()} {_c(YELLOW)}NOT required{_r()}", flush=True)


def print_dialect(dialect):
    if dialect == "SMB1":
        print(f"  {_c(RED)}dialect:{_r()} {_c(RED, BOLD)}{dialect}{_r()}", flush=True)
    else:
        print(f"  {_c(GREY)}dialect:{_r()} {dialect}", flush=True)


def print_progress(done, total):
    pct = done * 100 // total
    print(f"\r{_c(DIM)}[{done}/{total}] {pct}% hosts complete{_r()}",
          end="\n" if done == total else "", flush=True)


def print_share(share, writable=False, show_access=False):
    safe = _sanitise(share)
    if show_access:
        if writable:
            access = f"{_c(RED, BOLD)}READ/WRITE{_r()}"
        else:
            access = f"{_c(GREEN)}READ{_r()}"
        print(f"  {_c(GREEN)}[+]{_r()} {_c(BOLD)}{safe}{_r()}  {access}", flush=True)
    else:
        print(f"  {_c(GREEN)}[+]{_r()} {_c(BOLD)}{safe}{_r()}", flush=True)


def print_share_warning(share, message, critical=False):
    safe = _sanitise(share)
    if critical:
        print(f"  {_c(RED)}[!] {safe} — {message}{_r()}", flush=True)
    else:
        print(f"  {_c(YELLOW)}[!] {safe} — {message}{_r()}", flush=True)


def print_finding(host, share, path, tier, size, mtime, content_hits=None):
    tc = _c(COLORS.get(tier, ""))
    r = _r()
    dt_str = mtime.strftime("%Y-%m-%d") if mtime else "unknown"
    sz_str = human_size(size)
    tag = f"{tc}{tier:8s}{r}"
    meta = f"{_c(DIM)}{sz_str}  {dt_str}{_r()}"
    print(f"    {tag}  {_sanitise(path)}  {meta}", flush=True)
    if content_hits:
        for ct, _pat, lnum, line in content_hits:
            cc = _c(COLORS.get(ct, ""))
            print(f"    {_c(DIM)}         L{lnum}:{_r()} {cc}{_sanitise(line)}{r}", flush=True)


def print_loot(local_path):
    print(f"    {_c(MAGENTA)}>> looted:{_r()} {local_path}", flush=True)


def print_recon_share(entry):
    name = _sanitise(entry["share"])
    readable = entry["readable"]
    writable = entry["writable"]
    score = entry["score"]
    dirs = entry["dirs"]
    files = entry["files"]
    remark = entry.get("remark", "")

    if not readable:
        access = f"{_c(RED)}DENIED{_r()}"
    elif writable:
        access = f"{_c(RED, BOLD)}READ/WRITE{_r()}"
    else:
        access = f"{_c(GREEN)}READ{_r()}"

    if score >= 50:
        name_fmt = f"{_c(RED, BOLD)}{name}{_r()}"
        score_fmt = f"{_c(RED, BOLD)}{score}{_r()}"
    elif score >= 30:
        name_fmt = f"{_c(YELLOW, BOLD)}{name}{_r()}"
        score_fmt = f"{_c(YELLOW)}{score}{_r()}"
    else:
        name_fmt = f"{_c(WHITE)}{name}{_r()}"
        score_fmt = f"{_c(GREY)}{score}{_r()}"

    parts = [f"  {name_fmt:<40s}  {access:<20s}  score={score_fmt}"]
    meta = []
    if dirs or files:
        meta.append(f"{dirs}d/{files}f")
    if remark:
        meta.append(remark)
    if meta:
        parts.append(f"  {_c(DIM)}{' | '.join(meta)}{_r()}")

    print("".join(parts), flush=True)


# ── Banner ─────────────────────────────────────────────────────────────────

def print_banner(host_count, args):
    recon = getattr(args, "recon", False)
    mode = "RECON" if recon else "HUNT"
    from smbhunter import __version__
    print(f"\n{_c(BOLD, CYAN)}smbhunter{_r()} {_c(DIM)}v{__version__}{_r()}"
          f"  {_c(BOLD)}{mode}{_r()}"
          f"  {_c(DIM)}{host_count} target(s){_r()}", flush=True)

    parts = []
    auth = "kerberos" if getattr(args, "kerberos", False) else \
           "guest" if getattr(args, "guest", False) else \
           "hash" if args.hash else "password"
    parts.append(f"auth={auth}")
    if not recon:
        parts.append(f"tier>={args.min_tier}")
        if args.after:
            parts.append(f"after={args.after}")
        parts.append(f"depth={args.depth}")
        if args.content:
            parts.append("content")
        if getattr(args, "pattern", None):
            parts.append(f"+{len(args.pattern)} patterns")
        if getattr(args, "loot", None):
            parts.append(f"loot={args.loot}")
    if getattr(args, "write_check", False):
        parts.append("write-check")
    delay = getattr(args, "delay", 0)
    if delay:
        parts.append(f"delay={delay}ms")
    print(f"  {_c(DIM)}{' | '.join(parts)}{_r()}\n", flush=True)


# ── Summary ────────────────────────────────────────────────────────────────

def print_summary(elapsed, stats, results, errors, args=None):
    print(f"\n{_c(BOLD)}{'─'*60}{_r()}", flush=True)
    print(f"{_c(BOLD)}Completed{_r()} in {elapsed:.1f}s", flush=True)

    writable = stats.get("writable_shares", 0)
    share_str = f"{stats.get('readable_shares', 0)} readable"
    if writable:
        share_str += f" ({_c(RED, BOLD)}{writable} WRITABLE{_r()})"
    share_str += f", {stats.get('unreadable_shares', 0)} denied"
    print(f"  Shares:   {share_str}", flush=True)

    signing_req = stats.get("signing_required", 0)
    signing_not = stats.get("signing_not_required", 0)
    if signing_req or signing_not:
        s_parts = []
        if signing_req:
            s_parts.append(f"{signing_req} required")
        if signing_not:
            s_parts.append(f"{_c(YELLOW)}{signing_not} NOT required{_r()}")
        print(f"  Signing:  {', '.join(s_parts)}", flush=True)

    print(f"  Items:    {stats.get('total_items', 0)} total, "
          f"{stats.get('files_seen', 0)} files evaluated", flush=True)
    skip_parts = [
        f"{stats.get('skipped_dirs', 0)} dirs",
        f"{stats.get('skipped_old_dirs', 0)} old dirs",
        f"{stats.get('skipped_old_files', 0)} old files",
        f"{stats.get('skipped_large', 0)} oversized",
    ]
    if stats.get("skipped_ext"):
        skip_parts.append(f"{stats['skipped_ext']} by ext")
    print(f"  Skipped:  {', '.join(skip_parts)}", flush=True)
    if stats.get("deduped_files"):
        print(f"  Deduped:  {stats['deduped_files']} cross-share duplicates", flush=True)
    smbv1 = stats.get("smbv1_hosts", 0)
    if smbv1:
        print(f"  {_c(RED, BOLD)}SMBv1:    {smbv1} host(s) — consider reporting{_r()}", flush=True)

    tier_counts = defaultdict(int)
    for r in results:
        tier_counts[r["tier"]] += 1

    print(f"  {_c(BOLD)}Findings:{_r()}", flush=True)
    for tier in ALL_TIERS:
        if tier_counts[tier]:
            tc = _c(COLORS.get(tier, ""))
            print(f"    {tc}{tier:10s} {tier_counts[tier]}{_r()}", flush=True)

    if errors:
        print(f"  {_c(RED)}Errors: {len(errors)}{_r()}", flush=True)
        for err in errors:
            loc = f"{err['host']} [{err['share']}]" if err["share"] else err["host"]
            print(f"    {_c(RED)}- {loc}: {err['error']}{_r()}", flush=True)


def print_recon_summary(elapsed, stats, recon_results, errors):
    print(f"\n{_c(BOLD)}{'─'*60}{_r()}", flush=True)
    print(f"{_c(BOLD)}Recon complete{_r()} in {elapsed:.1f}s", flush=True)

    total_shares = len(recon_results)
    readable = sum(1 for r in recon_results if r["readable"])
    writable = sum(1 for r in recon_results if r["writable"])
    hosts = len(set(r["host"] for r in recon_results))

    print(f"  Hosts:    {hosts}", flush=True)
    share_str = f"{total_shares} total, {readable} readable"
    if writable:
        share_str += f", {_c(RED, BOLD)}{writable} WRITABLE{_r()}"
    print(f"  Shares:   {share_str}", flush=True)

    signing_req = stats.get("signing_required", 0)
    signing_not = stats.get("signing_not_required", 0)
    if signing_req or signing_not:
        s_parts = []
        if signing_req:
            s_parts.append(f"{signing_req} required")
        if signing_not:
            s_parts.append(f"{_c(YELLOW)}{signing_not} NOT required{_r()}")
        print(f"  Signing:  {', '.join(s_parts)}", flush=True)

    top = [r for r in recon_results if r["score"] >= 30 and r["readable"]]
    top.sort(key=lambda x: x["score"], reverse=True)
    if top:
        print(f"\n  {_c(BOLD)}Top targets:{_r()}", flush=True)
        for r in top[:15]:
            w = f" {_c(RED)}WRITE{_r()}" if r["writable"] else ""
            print(f"    {_c(YELLOW)}{r['score']:3d}{_r()}  "
                  f"{r['host']}\\\\{r['share']}{w}"
                  f"  {_c(DIM)}{r['dirs']}d/{r['files']}f{_r()}", flush=True)

    if errors:
        print(f"\n  {_c(RED)}Errors: {len(errors)}{_r()}", flush=True)


# ── File reports ───────────────────────────────────────────────────────────

def write_json_report(path, args, stats, results, errors):
    report = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "targets": args.targets,
        "mode": "hunt",
        "filters": {
            "after": args.after,
            "min_tier": args.min_tier,
            "depth": args.depth,
            "content_search": args.content,
        },
        "stats": dict(stats),
        "findings": results,
        "errors": errors,
    }
    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n{_c(GREEN)}[+]{_r()} JSON report: {path}", flush=True)


def write_json_recon_report(path, args, stats, recon_results, errors):
    report = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "targets": args.targets,
        "mode": "recon",
        "stats": dict(stats),
        "shares": recon_results,
        "errors": errors,
    }
    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n{_c(GREEN)}[+]{_r()} JSON recon report: {path}", flush=True)


def write_csv_report(path, results):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["host", "share", "path", "filename", "tier",
                          "size", "mtime", "content_summary"])
        for r in results:
            raw = "; ".join(
                f"L{h['line_num']}: {h['line']}" for h in r.get("content_hits", [])
            )
            content = raw[:297] + "..." if len(raw) > 300 else raw
            writer.writerow([
                r["host"], r["share"], r["path"], r["filename"],
                r["tier"], r["size"], r["mtime"], content,
            ])
    print(f"{_c(GREEN)}[+]{_r()} CSV report: {path}", flush=True)


def write_csv_recon_report(path, recon_results):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["host", "hostname", "share", "remark", "readable",
                          "writable", "dirs", "files", "score"])
        for r in recon_results:
            writer.writerow([
                r["host"], r.get("hostname", ""), r["share"],
                r.get("remark", ""), r["readable"], r["writable"],
                r["dirs"], r["files"], r["score"],
            ])
    print(f"{_c(GREEN)}[+]{_r()} CSV recon report: {path}", flush=True)
