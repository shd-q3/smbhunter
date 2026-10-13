"""Terminal and JSON output formatting."""

import json
import sys
from datetime import datetime, timezone

from smbhunter.tiers import COLORS, RESET, ALL_TIERS


def human_size(size_bytes):
    if size_bytes is None:
        return "?"
    for unit in ("B", "KB", "MB", "GB"):
        if abs(size_bytes) < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def supports_color():
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def print_finding(host, share, path, tier, size, mtime, content_hits=None):
    color = COLORS.get(tier, "") if supports_color() else ""
    reset = RESET if supports_color() else ""
    dt_str = mtime.strftime("%Y-%m-%d") if mtime else "unknown"
    sz_str = human_size(size)
    prefix = f"{color}[{tier:8s}]{reset}"
    print(f"  {prefix} {host} [{share}] {path}  ({sz_str}, {dt_str})", flush=True)
    if content_hits:
        for ct, _pat, lnum, line in content_hits:
            ccolor = COLORS.get(ct, "") if supports_color() else ""
            print(f"           {ccolor}L{lnum}: {line}{reset}", flush=True)


def write_json_report(path, args, stats, results, errors):
    report = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "targets": args.targets,
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
    print(f"\n[+] Report saved: {path}", flush=True)


def print_banner(host_count, args):
    print(f"[*] smbhunter v0.2.0 — {host_count} target(s)", flush=True)
    delay = getattr(args, "delay", 0)
    delay_str = f", delay={delay}ms" if delay else ""
    print(f"[*] Filters: after={args.after or 'none'}, min_tier={args.min_tier}, "
          f"depth={args.depth}, content={args.content}{delay_str}", flush=True)


def print_summary(elapsed, stats, results, errors, output_path=None, args=None):
    color = supports_color()
    print(f"\n{'='*60}", flush=True)
    print(f"[*] Completed in {elapsed:.1f}s", flush=True)
    print(f"    Shares: {stats['readable_shares']} readable, "
          f"{stats['unreadable_shares']} denied", flush=True)

    signing_req = stats.get("signing_required", 0)
    signing_not = stats.get("signing_not_required", 0)
    if signing_req or signing_not:
        print(f"    Signing: {signing_req} required, {signing_not} NOT required", flush=True)

    print(f"    Items:  {stats['total_items']} total, "
          f"{stats['files_seen']} files evaluated", flush=True)
    print(f"    Skipped: {stats['skipped_dirs']} system dirs, "
          f"{stats['skipped_old_dirs']} old year dirs, "
          f"{stats['skipped_old_files']} old files, "
          f"{stats['skipped_large']} oversized", flush=True)

    from collections import defaultdict
    tier_counts = defaultdict(int)
    for r in results:
        tier_counts[r["tier"]] += 1

    print("    Findings:", flush=True)
    for tier in ALL_TIERS:
        if tier_counts[tier]:
            c = COLORS.get(tier, "") if color else ""
            r = RESET if color else ""
            print(f"      {c}{tier:10s}: {tier_counts[tier]}{r}", flush=True)

    if errors:
        red = "\033[91m" if color else ""
        r = RESET if color else ""
        print(f"    {red}Errors: {len(errors)}{r}", flush=True)
        for err in errors:
            host = err["host"]
            share = err["share"]
            msg = err["error"]
            loc = f"{host} [{share}]" if share else host
            print(f"      {red}- {loc}: {msg}{r}", flush=True)

    if output_path and args:
        write_json_report(output_path, args, stats, results, errors)
