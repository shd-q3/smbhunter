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
  smbhunter targets.txt -u admin -p 'Pass123!' -d CORP --after 2025-01-01 --content
  smbhunter 10.0.0.5 -u admin -H aad3b435b51404eeaad3b435b51404ee:ntlmhash -d CORP
  smbhunter targets.txt -u admin -p pass -d CORP --min-tier HIGH --depth 5 -o report.json
  smbhunter dc01 -u admin -p pass -d CORP --shares NETLOGON,SYSVOL --content
        """,
    )

    parser.add_argument("targets", help="single host/IP or file with one host per line")
    parser.add_argument("-u", "--username", required=True, help="username for authentication")
    parser.add_argument("-p", "--password", default="", help="password")
    parser.add_argument("-H", "--hash", default=None, help="NTLM hash (LM:NT format)")
    parser.add_argument("-d", "--domain", default=".", help="domain (default: .)")

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

    scan = parser.add_argument_group("scanning")
    scan.add_argument("--content", action="store_true",
                      help="download + grep small text files for credentials")
    scan.add_argument("--shares", default=None, metavar="SHARE1,SHARE2",
                      help="only scan these shares (comma-separated)")
    scan.add_argument("--delay", type=int, default=0, metavar="MS",
                      help="delay between file operations in ms (default: 0)")
    scan.add_argument("--threads", "-t", type=int, default=5,
                      help="parallel host threads (default: 5)")
    scan.add_argument("--timeout", type=int, default=5,
                      help="SMB connection timeout seconds (default: 5)")

    out = parser.add_argument_group("output")
    out.add_argument("-o", "--output", default=None, metavar="FILE",
                     help="write JSON report to FILE")
    out.add_argument("--logfile", default=None, metavar="FILE",
                     help="write detailed log to FILE (auditable)")
    out.add_argument("--debug", action="store_true",
                     help="enable debug-level logging")
    out.add_argument("-v", "--version", action="version",
                     version=f"smbhunter {__version__}")

    args = parser.parse_args()

    if not args.password and not args.hash:
        parser.error("either -p/--password or -H/--hash is required")

    hunter = SMBHunter(args)
    try:
        hunter.run()
    except KeyboardInterrupt:
        print("\n[!] Interrupted", flush=True)
        sys.exit(130)
