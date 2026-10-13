"""CLI entry point for smbhunter."""

import argparse
import sys

from smbhunter import __version__
from smbhunter.hunter import SMBHunter


def main():
    parser = argparse.ArgumentParser(
        prog="smbhunter",
        description="smbhunter — smart SMB share enumerator with tiered severity, "
                    "date-aware recursion, and content search",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  smbhunter 10.0.0.5 -u admin -p 'Pass123!' -d CORP
  smbhunter 10.0.0.0/24 -u admin -p 'Pass123!' -d CORP --content
  smbhunter targets.txt -u admin -H aad3b435b51404eeaad3b435b51404ee:hash -d CORP
  smbhunter dc01 -u admin -p pass -d CORP --shares NETLOGON,SYSVOL --content
  smbhunter dc01 -k -d CORP --content                       # Kerberos (ccache)
  smbhunter 10.0.0.0/24 --guest                             # null/guest session
  smbhunter dc01 -u admin -p pass -d CORP --content --loot ./loot
  smbhunter dc01 -u admin -p pass -d CORP --content --pattern 'ACME\\\\svc\\.'
  smbhunter dc01 -u admin -p pass -d CORP --write-check -o report.json --csv report.csv
        """,
    )

    parser.add_argument("targets", help="host, IP, CIDR, or file with one target per line")

    auth = parser.add_argument_group("authentication")
    auth.add_argument("-u", "--username", default="", help="username")
    auth.add_argument("-p", "--password", default="", help="password")
    auth.add_argument("-H", "--hash", default=None, help="NTLM hash (LM:NT format)")
    auth.add_argument("-d", "--domain", default=".", help="domain (default: .)")
    auth.add_argument("-k", "--kerberos", action="store_true",
                      help="use Kerberos auth (respects KRB5CCNAME)")
    auth.add_argument("--dc-ip", default=None, dest="dc_ip", metavar="IP",
                      help="domain controller IP (for Kerberos when DNS fails)")
    auth.add_argument("--guest", action="store_true",
                      help="attempt guest/anonymous session (no creds needed)")

    filt = parser.add_argument_group("filters")
    filt.add_argument("--after", default=None, metavar="YYYY-MM-DD",
                      help="skip files modified before this date")
    filt.add_argument("--min-tier", default="LOW", dest="min_tier",
                      choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                      help="minimum severity to display (default: LOW)")
    filt.add_argument("--depth", type=int, default=10,
                      help="max directory recursion depth (default: 10)")
    filt.add_argument("--max-size", type=int, default=50, dest="max_size",
                      help="skip files larger than N MB (default: 50)")
    filt.add_argument("--exclude-dirs", nargs="*", default=None, dest="exclude_dirs",
                      metavar="DIR", help="additional directory names to skip")
    filt.add_argument("--exclude-ext", nargs="*", default=None, dest="exclude_ext",
                      metavar="EXT", help="skip files with these extensions (e.g. .dll .exe)")

    scan = parser.add_argument_group("scanning")
    scan.add_argument("--recon", action="store_true",
                      help="recon mode — enumerate shares, score by interest, don't spider")
    scan.add_argument("--content", action="store_true",
                      help="download + grep small text files for credentials")
    scan.add_argument("--pattern", action="append", default=None, metavar="REGEX",
                      help="custom content regex — implies --content (repeatable)")
    scan.add_argument("--shares", default=None, metavar="SHARE1,SHARE2",
                      help="only scan these shares (comma-separated)")
    scan.add_argument("--loot", default=None, metavar="DIR",
                      help="auto-download CRITICAL files to this directory")
    scan.add_argument("--write-check", action="store_true", dest="write_check",
                      help="test write access per share (creates+deletes a test file)")
    scan.add_argument("--delay", type=int, default=0, metavar="MS",
                      help="delay between file operations in ms (default: 0)")
    scan.add_argument("--threads", "-t", type=int, default=5,
                      help="parallel host threads (default: 5)")
    scan.add_argument("--timeout", type=int, default=5,
                      help="SMB connection timeout seconds (default: 5)")
    scan.add_argument("--resume", action="store_true",
                      help="skip hosts already in the JSONL stream (requires -o)")

    out = parser.add_argument_group("output")
    out.add_argument("-o", "--output", default=None, metavar="FILE",
                     help="write JSON report to FILE")
    out.add_argument("--csv", default=None, metavar="FILE",
                     help="write CSV report to FILE")
    out.add_argument("--logfile", default=None, metavar="FILE",
                     help="write detailed log to FILE (auditable)")
    out.add_argument("--debug", action="store_true",
                     help="enable debug-level logging")
    out.add_argument("-v", "--version", action="version",
                     version=f"smbhunter {__version__}")

    args = parser.parse_args()

    if args.pattern:
        args.content = True

    if not args.guest and not args.kerberos:
        if not args.username:
            parser.error("-u/--username required (or use --guest / -k)")
        if not args.password and not args.hash:
            parser.error("-p/--password or -H/--hash required (or use --guest / -k)")

    hunter = SMBHunter(args)
    try:
        hunter.run()
    except KeyboardInterrupt:
        print("\n[!] Interrupted — flushing partial results", flush=True)
        hunter.flush_reports()
        sys.exit(130)
