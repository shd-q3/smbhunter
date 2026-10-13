# smbhunter

Smart SMB share enumerator that combines inventory, content search, and severity classification.

Crawls accessible SMB shares and classifies every file into a severity tier (CRITICAL / HIGH / MEDIUM / LOW / INFO) based on extension, filename keywords, and content regex. Built for pentesters who need more signal and less noise from share enumeration.

## Features

- **Tiered severity** — files ranked by risk: private keys and credential stores at the top, office docs and logs at the bottom
- **Content search** — downloads small text files and greps for hardcoded passwords, API keys, connection strings, tokens (AWS, GitHub, Stripe, Vault, etc.)
- **Date-aware recursion** — `--after` skips old files and prunes year-named directories (e.g. `\2019\`)
- **Windows noise suppression** — ADMIN$ and C$ system paths automatically demoted to INFO
- **SMB signing detection** — reports signing status per host
- **Audit logging** — full timestamped log for engagement evidence
- **Rate limiting** — `--delay` throttles file operations to avoid impacting production servers
- **Reconnect** — recovers from dropped SMB sessions mid-scan

## Install

```bash
pip install .
```

Or editable for development:

```bash
pip install -e .
```

Requires Python 3.10+ and [impacket](https://github.com/fortra/impacket).

## Usage

```bash
# Basic scan
smbhunter 10.0.0.5 -u admin -p 'Pass123!' -d CORP

# With content search and date filter
smbhunter targets.txt -u admin -p 'Pass123!' -d CORP --after 2025-01-01 --content

# NTLM hash authentication
smbhunter 10.0.0.5 -u admin -H aad3b435b51404eeaad3b435b51404ee:ntlmhash -d CORP

# Specific shares only, with audit trail
smbhunter dc01 -u admin -p pass -d CORP --shares NETLOGON,SYSVOL --content --logfile scan.log -o report.json

# Production-safe with rate limiting
smbhunter targets.txt -u svc.audit -p pass -d CORP --content --delay 100 --logfile audit.log -o findings.json
```

## Options

```
targets                     single host/IP or file with one host per line

Authentication:
  -u, --username            username
  -p, --password            password
  -H, --hash                NTLM hash (LM:NT format)
  -d, --domain              domain (default: .)

Filters:
  --after YYYY-MM-DD        skip files modified before this date
  --min-tier TIER           minimum severity to display (default: LOW)
  --depth N                 max directory recursion depth (default: 10)
  --max-size N              skip files larger than N MB (default: 50)
  --exclude-dirs DIR...     additional directory names to skip

Scanning:
  --content                 download + grep small text files for credentials
  --shares SHARE1,SHARE2   only scan these shares
  --delay MS                delay between file operations in ms (default: 0)
  -t, --threads N           parallel host threads (default: 5)
  --timeout N               SMB connection timeout seconds (default: 5)

Output:
  -o, --output FILE         write JSON report to FILE
  --logfile FILE            write detailed log to FILE
  --debug                   enable debug-level logging
```

## Severity Tiers

| Tier | Examples |
|------|----------|
| CRITICAL | `.kdbx`, `.pem`, `.pfx`, `password` in filename, `cpassword` in content |
| HIGH | `.ps1`, `.bat`, `token` in filename, API keys in content |
| MEDIUM | `.config`, `.env`, `.sql`, `admin`/`vpn` in filename |
| LOW | `.xlsx`, `.pdf`, `.txt`, `.zip` |
| INFO | System noise, unclassified files |

## JSON Report

The `-o` flag produces a structured JSON report containing:

- Scan metadata (time, targets, filters)
- Statistics (shares, files, skipped items)
- All findings with tier, path, size, mtime, and content matches
- Errors (failed connections, dropped sessions)

## License

MIT
