# smbhunter

Fast SMB share enumeration with teeth. Crawls every readable share, classifies files by risk, greps for hardcoded credentials, and auto-downloads the good stuff — so you spend less time sifting and more time pwning.

Think spider_plus meets manspider meets snaffler, in one `pip install`.

## Why

Share enumeration during an engagement usually means:
1. Spider everything, drown in 50k files
2. Manually grep for passwords, miss half of them
3. No idea which of 200 hosts to hit first

smbhunter fixes all three. **Recon mode** scores every share across the network so you know where to look. **Hunt mode** classifies every file by severity, greps content for credentials, and auto-loots the critical stuff.

## Quick start

```bash
pip install .

# Recon first — find interesting shares across the subnet
smbhunter 10.0.0.0/24 -u svc.audit -p 'Aud1t!' -d CORP --recon --write-check

# Hunt the interesting ones
smbhunter 10.0.0.0/24 -u svc.audit -p 'Aud1t!' -d CORP --content --loot ./loot -o findings.json
```

## Modes

### Recon mode (`--recon`)

Enumerates shares across the network without spidering. Scores each share by name, access level, and contents. Tells you where to look first.

```bash
smbhunter 10.0.0.0/24 -u admin -p pass -d CORP --recon --write-check -o recon.json --csv recon.csv
```

Output ranks shares by score — high-value names (backup, finance, deploy, credentials), writable access, and directory depth all contribute. Top targets are highlighted. SMB dialect and signing are reported per host.

### Hunt mode (default)

Full spider with severity classification, content search, and auto-loot.

```bash
# Kitchen sink
smbhunter targets.txt -u admin -p pass -d CORP --content --loot ./loot \
  --write-check --pattern 'CORP\\svc\.' --delay 50 \
  --logfile audit.log -o findings.json --csv findings.csv

# Quick high-value sweep
smbhunter dc01 -u admin -p pass -d CORP --content --min-tier HIGH --shares NETLOGON,SYSVOL

# Skip noisy binaries on C$
smbhunter dc01 -u admin -p pass -d CORP --exclude-ext .dll .exe .sys .mui

# Resume after interruption
smbhunter 10.0.0.0/24 -u admin -p pass -d CORP --content -o findings.json --resume
```

## Features

- **CIDR support** — `10.0.0.0/24` expands automatically, or pass a target file
- **Severity tiers** — CRITICAL down to INFO based on extension, filename, and content
- **Content grep** — ~30 credential patterns: connection strings, `net use` creds, AWS keys, GitHub PATs, Vault tokens, cpassword, docker-compose secrets
- **Custom patterns** — `--pattern 'REGEX'` to add engagement-specific greps (repeatable)
- **Auto-loot** — `--loot ./dir` downloads all CRITICAL files, preserving directory structure
- **Write-access check** — `--write-check` tests if shares are writable (creates+deletes a test file)
- **SMB dialect detection** — reports SMBv1/2/3 per host, flags SMBv1 in summary
- **SMB signing** — reports signing status per host
- **Cross-share dedup** — same file visible via C$ and a named share only appears once
- **Extension filter** — `--exclude-ext .dll .exe` to skip noisy file types
- **Date filtering** — `--after 2024-01-01` skips old files and prunes year-named dirs
- **Noise suppression** — ADMIN$ fully suppressed, C$ system paths demoted to INFO
- **Kerberos** — `-k` with KRB5CCNAME ccache support
- **Guest/null session** — `--guest` for unauthenticated enumeration
- **Rate limiting** — `--delay` throttles file ops for production environments
- **Progress counter** — `[15/254] 5% hosts complete` on multi-host scans
- **Resume** — `--resume` skips hosts already in the JSONL stream after Ctrl+C
- **Audit trail** — `--logfile` for timestamped audit log
- **Reconnect** — recovers from dropped SMB sessions mid-scan
- **Crash-safe** — JSONL streaming means partial results survive Ctrl+C
- **CSV + JSON** — structured output for reporting and automation
- **Proxychains compatible** — for pivoting, use `proxychains smbhunter ...`

## Authentication

```bash
# Password
smbhunter target -u admin -p 'Pass123!' -d CORP

# NTLM hash
smbhunter target -u admin -H aad3b435b51404eeaad3b435b51404ee:hash -d CORP

# Kerberos (ccache)
export KRB5CCNAME=/tmp/krb5cc_admin
smbhunter target -k -d CORP --dc-ip 10.0.0.1

# Guest/null session
smbhunter target --guest
```

## Options

```
targets                     host, IP, CIDR, or file (one per line)

Authentication:
  -u, --username            username
  -p, --password            password
  -H, --hash                NTLM hash (LM:NT)
  -d, --domain              domain (default: .)
  -k, --kerberos            use Kerberos (KRB5CCNAME)
  --dc-ip IP                DC IP for Kerberos
  --guest                   guest/anonymous session

Scanning:
  --recon                   recon mode — score shares, don't spider
  --content                 grep files for credential patterns
  --pattern REGEX           custom content regex (repeatable)
  --shares S1,S2            limit to specific shares
  --loot DIR                auto-download CRITICAL files
  --write-check             test write access per share
  --delay MS                throttle between file ops (ms)
  -t N                      host threads (default: 5)
  --timeout N               connection timeout (default: 5s)
  --resume                  skip hosts already in JSONL (requires -o)

Filters:
  --after YYYY-MM-DD        skip files older than this
  --min-tier TIER           display threshold (default: LOW)
  --depth N                 max recursion (default: 10)
  --max-size N              skip files > N MB (default: 50)
  --exclude-dirs DIR...     skip these directory names
  --exclude-ext EXT...      skip these file extensions (e.g. .dll .exe)

Output:
  -o FILE                   JSON report
  --csv FILE                CSV report
  --logfile FILE            audit log
  --debug                   verbose logging
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

Python 3.10+ and [impacket](https://github.com/fortra/impacket).

## License

MIT
