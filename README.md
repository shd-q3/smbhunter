# smbhunter

Fast SMB share enumeration with teeth. Crawls every readable share, classifies files by risk, and greps for hardcoded credentials — so you spend less time sifting and more time pwning.

Think spider_plus meets manspider meets snaffler, in one `pip install`.

## Why

Share enumeration during an engagement usually means:
1. Spider everything → drown in 50k files
2. Manually grep for passwords → miss half of them
3. Ignore low-tier noise → miss the `.env` with `DB_PASS=` inside

smbhunter fixes all three. Every file gets a severity tier. Content search catches what filenames don't. System noise gets killed before you see it.

## Quick start

```bash
pip install .
smbhunter dc01.corp.local -u svc.audit -p 'Aud1t!' -d CORP --content -o loot.json
```

## What it does

**Severity tiers** — CRITICAL down to INFO based on extension, filename keywords, and content patterns. Private keys and KeePass databases float to the top. Office docs and logs sink to the bottom.

**Content grep** — Downloads small text files and matches against ~30 credential patterns: connection strings, `net use` creds, AWS keys, GitHub PATs, Vault tokens, cpassword, docker-compose secrets, and more.

**Date filtering** — `--after 2024-01-01` skips stale files and prunes year-named directories like `\2019\`.

**Noise suppression** — ADMIN$ is fully suppressed. C$ system paths (Windows, Program Files, WinSxS, etc.) are demoted to INFO. No more scrolling past 10k DLL manifests.

**SMB signing** — Reports signing status per host. Free finding for the report.

**Audit trail** — `--logfile` writes a timestamped log of every action. `--delay` throttles requests for production environments.

**Reconnect** — Recovers from dropped SMB sessions mid-scan without losing progress.

## Usage

```bash
# Scan with content search
smbhunter 10.0.0.0/24 -u admin -p pass -d CORP --content

# Hash auth
smbhunter dc01 -u admin -H aad3b435b51404eeaad3b435b51404ee:hash -d CORP

# Target specific shares
smbhunter dc01 -u admin -p pass -d CORP --shares NETLOGON,SYSVOL --content

# Production-safe: 100ms delay, full audit log
smbhunter targets.txt -u svc.audit -p pass -d CORP --content --delay 100 --logfile audit.log -o findings.json

# Only show high-value stuff
smbhunter dc01 -u admin -p pass -d CORP --min-tier HIGH --content
```

## Options

```
targets                     host, IP, or file (one per line)

-u, --username              auth username
-p, --password              auth password
-H, --hash                  NTLM hash (LM:NT)
-d, --domain                domain (default: .)

--after YYYY-MM-DD          skip files older than this
--min-tier TIER             display threshold (default: LOW)
--depth N                   max recursion (default: 10)
--max-size N                skip files > N MB (default: 50)
--content                   grep files for credential patterns
--shares S1,S2              limit to specific shares
--delay MS                  throttle between file ops (ms)
-t N                        host threads (default: 5)
-o FILE                     JSON report output
--logfile FILE              audit log output
--debug                     verbose logging
```

## Tiers

| Tier | What triggers it |
|------|-----------------|
| CRITICAL | `.kdbx`, `.pem`, `.pfx`, `password`/`cpassword` in name, creds in content |
| HIGH | `.ps1`, `.bat`, `token`/`apikey` in name, API keys in content |
| MEDIUM | `.config`, `.env`, `.sql`, `.bak`, `admin`/`vpn` in name |
| LOW | `.xlsx`, `.pdf`, `.txt`, `.zip` |
| INFO | OS noise, unclassified |

## Install

```bash
git clone https://github.com/shd-q3/smbhunter.git
cd smbhunter
pip install .
```

Needs Python 3.10+ and [impacket](https://github.com/fortra/impacket).

## License

MIT
