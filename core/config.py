"""
core/config.py — Paths, constants, and tool/wordlist metadata.
"""

from pathlib import Path

# ── Output root ────────────────────────────────────────────────────────────────
OUTPUT_BASE = Path.home() / "Desktop"

# ── Wordlist search paths ──────────────────────────────────────────────────────
# Searched in order; first match wins.
WORDLIST_SEARCH_PATHS = [
    Path("/usr/share/seclists"),
    Path("/usr/share/wordlists"),
    Path.home() / "wordlists",
    Path.home() / "SecLists",
    Path("/opt/SecLists"),
    Path("/usr/local/share/seclists"),
]

# ── Wordlist registry ──────────────────────────────────────────────────────────
# key → (relative path inside SecLists or wordlists, description, download hint)
WORDLIST_REGISTRY = {
    "dns_brute": (
        "Discovery/DNS/subdomains-top1million-5000.txt",
        "DNS brute-force subdomain list",
        "https://github.com/danielmiessler/SecLists",
    ),
    "dns_brute_large": (
        "Discovery/DNS/subdomains-top1million-20000.txt",
        "DNS brute-force (large) subdomain list",
        "https://github.com/danielmiessler/SecLists",
    ),
    "dir_medium": (
        "Discovery/Web-Content/directory-list-2.3-medium.txt",
        "Directory fuzzing wordlist (medium)",
        "https://github.com/danielmiessler/SecLists",
    ),
    "dir_big": (
        "Discovery/Web-Content/big.txt",
        "Directory fuzzing wordlist (big)",
        "https://github.com/danielmiessler/SecLists",
    ),
    "api_routes": (
        "Discovery/Web-Content/api/api-endpoints.txt",
        "API endpoint fuzzing wordlist",
        "https://github.com/danielmiessler/SecLists",
    ),
    "params": (
        "Discovery/Web-Content/burp-parameter-names.txt",
        "HTTP parameter names wordlist",
        "https://github.com/danielmiessler/SecLists",
    ),
}


def resolve_wordlist(key: str) -> Path | None:
    """Return absolute path to a wordlist or None if not found."""
    rel, _, _ = WORDLIST_REGISTRY[key]
    for base in WORDLIST_SEARCH_PATHS:
        candidate = base / rel
        if candidate.exists():
            return candidate
    return None


# ── Tool registry ──────────────────────────────────────────────────────────────
# key → (binary_name, install_hint)
TOOL_REGISTRY = {
    # subdomains
    "subfinder":      ("subfinder",      "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    "amass":          ("amass",          "go install -v github.com/owasp-amass/amass/v4/...@master  OR  apt install amass"),
    "assetfinder":    ("assetfinder",    "go install github.com/tomnomnom/assetfinder@latest"),
    # dns
    "dnsx":           ("dnsx",           "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
    "massdns":        ("massdns",        "apt install massdns  OR  build from https://github.com/blechschmidt/massdns"),
    # http
    "httpx":          ("httpx",          "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    "wafw00f":        ("wafw00f",        "pip install wafw00f"),
    "whatweb":        ("whatweb",        "apt install whatweb  OR  gem install whatweb"),
    # crawl
    "katana":         ("katana",         "go install github.com/projectdiscovery/katana/cmd/katana@latest"),
    "gau":            ("gau",            "go install github.com/lc/gau/v2/cmd/gau@latest"),
    "waybackurls":    ("waybackurls",    "go install github.com/tomnomnom/waybackurls@latest"),
    # fuzzing
    "ffuf":           ("ffuf",           "go install github.com/ffuf/ffuf/v2@latest"),
    "feroxbuster":    ("feroxbuster",    "cargo install feroxbuster  OR  apt install feroxbuster"),
    # params
    "arjun":          ("arjun",          "pip install arjun"),
    # portscan
    "nmap":           ("nmap",           "apt install nmap"),
    # vulnscan
    "nuclei":         ("nuclei",         "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    # screenshots
    "gowitness":      ("gowitness",      "go install github.com/sensepost/gowitness@latest"),
    # secrets
    "trufflehog":     ("trufflehog",     "brew install trufflehog  OR  go install github.com/trufflesecurity/trufflehog/v3@latest"),
    "gitleaks":       ("gitleaks",       "go install github.com/gitleaks/gitleaks/v8@latest  OR  apt install gitleaks"),
    # cloud
    "cloud_enum":     ("cloud_enum",     "pip install cloud-enum  OR  git clone https://github.com/initstring/cloud_enum"),
    # js analysis
    "linkfinder":     ("linkfinder",     "pip install linkfinder  OR  git clone https://github.com/GerbenJavado/LinkFinder"),
    "secretfinder":   ("secretfinder",   "git clone https://github.com/m4ll0k/SecretFinder  (run as python3 SecretFinder.py)"),
    # dns utils
    "dig":            ("dig",            "apt install dnsutils"),
}

# ── Module → required tools mapping ───────────────────────────────────────────
MODULE_TOOL_REQUIREMENTS = {
    "subdomains": {
        "required": [],
        "optional": ["subfinder", "amass", "assetfinder"],
        "note": "At least one of subfinder / amass / assetfinder must be present",
    },
    "dns": {
        "required": ["dnsx"],
        "optional": ["massdns", "dig"],
    },
    "http_probe": {
        "required": ["httpx"],
        "optional": ["wafw00f", "whatweb"],
    },
    "crawl": {
        "required": [],
        "optional": ["katana", "gau", "waybackurls"],
        "note": "At least one crawler must be present",
    },
    "fuzzing": {
        "required": [],
        "optional": ["ffuf", "feroxbuster"],
        "note": "At least one fuzzer must be present",
    },
    "params": {
        "required": ["arjun"],
        "optional": [],
    },
    "portscan": {
        "required": ["nmap"],
        "optional": [],
    },
    "vulnscan": {
        "required": ["nuclei"],
        "optional": [],
    },
    "screenshots": {
        "required": ["gowitness"],
        "optional": [],
    },
    "secrets": {
        "required": [],
        "optional": ["trufflehog", "gitleaks"],
        "note": "At least one secret scanner must be present",
    },
    "js_analysis": {
        "required": [],
        "optional": ["linkfinder", "secretfinder"],
        "note": "At least one JS analysis tool must be present",
    },
    "cloud": {
        "required": ["cloud_enum"],
        "optional": [],
    },
}

# ── Module → required wordlists mapping ───────────────────────────────────────
MODULE_WORDLIST_REQUIREMENTS = {
    "dns":     ["dns_brute"],
    "fuzzing": ["dir_medium"],
}
