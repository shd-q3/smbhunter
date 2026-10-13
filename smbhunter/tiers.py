"""Severity tier definitions, extension maps, keyword maps, and content patterns."""

CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
INFO = "INFO"

ALL_TIERS = [CRITICAL, HIGH, MEDIUM, LOW, INFO]

COLORS = {
    CRITICAL: "\033[91m",   # red
    HIGH:     "\033[93m",   # yellow
    MEDIUM:   "\033[96m",   # cyan
    LOW:      "\033[37m",   # white
    INFO:     "\033[90m",   # grey
}
RESET = "\033[0m"

# ── Extension → tier ────────────────────────────────────────────────────────

EXT_TIERS = {
    CRITICAL: {
        ".kdbx", ".kdb", ".ppk", ".pem", ".pfx", ".p12", ".key", ".keystore",
        ".jks", ".rdp", ".rdg", ".rtsz", ".pcap", ".pcapng", ".dmp",
    },
    HIGH: {
        ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe", ".wsf",
        ".js", ".hta", ".sct", ".inf", ".reg",
    },
    MEDIUM: {
        ".config", ".conf", ".cfg", ".ini", ".env", ".xml", ".json", ".yml",
        ".yaml", ".toml", ".properties", ".pst", ".ost", ".mdb", ".accdb",
        ".sqlite", ".db", ".sql", ".bak", ".old", ".orig", ".backup",
        ".vmdk", ".vhd", ".vhdx", ".ova",
        ".tf", ".tfvars", ".hcl",
    },
    LOW: {
        ".xlsx", ".xls", ".xlsm", ".docx", ".doc", ".docm", ".pptx",
        ".csv", ".pdf", ".txt", ".log", ".zip", ".7z", ".rar", ".tar",
        ".gz",
    },
}

# ── Filename keyword → tier (case-insensitive) ─────────────────────────────

KEYWORD_TIERS = {
    CRITICAL: [
        "password", "passwd", "credential", "secret", "private.key",
        "id_rsa", "id_ed25519", "keepass", "vault", "master",
        "unattend", "cpassword",
    ],
    HIGH: [
        "login", "logon", "token", "apikey", "api_key", "api-key",
        "connectionstring", "conn_str", "backup", "dump", "cred",
    ],
    MEDIUM: [
        "config", "setup", "install", "deploy", "admin", "vpn",
        "firewall", "network", "database", "account", "finance",
        "salary", "payroll", "hr",
    ],
}

# ── Content regex patterns for file grep ────────────────────────────────────

CONTENT_PATTERNS = {
    CRITICAL: [
        r'password\s*[=:]\s*\S+',
        r'passwd\s*[=:]\s*\S+',
        r'pwd\s*[=:]\s*\S+',
        r'_PASS\s*[=:]\s*\S+',
        r'_PASSWORD\s*[=:]\s*\S+',
        r'_SECRET\s*[=:]\s*\S+',
        r'connectionstring\s*[=:].+password',
        r'"password"\s*:\s*"[^"]+"',
        r'net\s+use\s+.+/user:',
        r'ConvertTo-SecureString',
        r'SecureString',
        r'PSCredential',
        r'PRIVATE\s+KEY',
        r'[Pp]assword[Ss]ecret\s*[>=:]\s*\S+',
        r'cpassword\s*[=:"]\S+',
        r'MYSQL_ROOT_PASSWORD\s*[=:]\s*\S+',
        r'MYSQL_PASSWORD\s*[=:]\s*\S+',
        r'password\s+\d+:b:\S+',
    ],
    HIGH: [
        r'(?:user|usr|login|account)\s*[=:]\s*\S+',
        r'(?<!publickey)token\s*[=:]\s*\S+',
        r'api[_-]?key\s*[=:]\s*\S+',
        r'secret\s*[=:]\s*\S+',
        r'(?:jdbc|odbc|server).*(?:user|pass|pwd)',
        r'runas\s+/user:',
        r'schtasks.+/ru\s',
        r'(?:access_key|secret_key|aws_)\s*[=:]\s*\S+',
        r'(?:ghp_|gho_|github_pat_)\w{10,}',
        r'sk_live_\w+',
        r'hvs\.\w{20,}',
        r'SG\.\w{20,}',
    ],
}

# ── Grep-eligible file extensions ───────────────────────────────────────────

CONTENT_EXTS = {
    ".txt", ".csv", ".log", ".ps1", ".bat", ".cmd", ".vbs", ".xml",
    ".config", ".ini", ".env", ".json", ".yml", ".yaml", ".cfg",
    ".conf", ".properties", ".inf", ".reg", ".sql", ".py", ".sh",
    ".tf", ".tfvars", ".hcl", ".rdp", ".php",
}

CONTENT_FILENAMES = {
    ".gitconfig", ".npmrc", ".pypirc", ".netrc", ".env",
    ".htpasswd", ".pgpass", ".dockerenv",
}
