# recon

A modular, fast reconnaissance framework that chains the best open-source tools into a single automated pipeline — from subdomain discovery to vulnerability scanning, secrets detection, and cloud asset enumeration.

```
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
```

---

## Features

| Module | Tools | What it does |
|---|---|---|
| **subdomains** | subfinder, amass, assetfinder | Passive + active subdomain enumeration, deduplicated |
| **dns** | dnsx, massdns, dig | Resolve subdomains, DNS brute-force, AXFR zone transfer |
| **http_probe** | httpx, wafw00f, whatweb | Probe live hosts, detect WAFs, fingerprint tech stack |
| **crawl** | katana, gau, waybackurls | Crawl live URLs + harvest historical endpoints |
| **fuzzing** | ffuf, feroxbuster | Directory and path fuzzing per live host |
| **params** | arjun | Discover hidden HTTP parameters |
| **portscan** | nmap | Port scan with user-selected profile (interactive) |
| **vulnscan** | nuclei | Template-based vuln/misconfig scanning |
| **screenshots** | gowitness | Screenshot every live URL *(optional, prompted)* |
| **secrets** | trufflehog, gitleaks | Scan for leaked secrets and credentials |
| **cloud** | cloud_enum | Enumerate S3, Azure Blob, GCP Storage buckets |

All output lands in `~/Desktop/<domain>-RECON/` with one subfolder per module.

---

## Requirements

### Python

- Python 3.10+
- One pip dependency:

```bash
pip install rich
```

Or:

```bash
pip install -r requirements.txt
```

### External Tools

The framework will tell you exactly what's missing at startup. Nothing is hard-required — each module degrades gracefully if optional tools are absent, and at least one tool per module must be present for that module to run.

#### Quick install (Go tools)

```bash
# Make sure ~/go/bin is in your PATH
export PATH=$PATH:$(go env GOPATH)/bin

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install    github.com/tomnomnom/assetfinder@latest
go install    github.com/tomnomnom/waybackurls@latest
go install    github.com/lc/gau/v2/cmd/gau@latest
go install    github.com/ffuf/ffuf/v2@latest
go install    github.com/sensepost/gowitness@latest
go install    github.com/trufflesecurity/trufflehog/v3@latest
go install    github.com/gitleaks/gitleaks/v8@latest
```

#### Package manager tools

```bash
# Debian / Ubuntu / Kali
sudo apt install amass nmap massdns whatweb dnsutils

# pip
pip install wafw00f arjun cloud-enum

# feroxbuster
cargo install feroxbuster
# OR: apt install feroxbuster  (Kali)
```

### Wordlists (SecLists)

The framework needs SecLists for DNS brute-force and directory fuzzing. If they're missing the relevant modules are skipped and you're told exactly what to install.

```bash
# Kali / Parrot (already included)
# Manual install:
sudo git clone https://github.com/danielmiessler/SecLists /usr/share/seclists
```

Expected paths (searched in order):
- `/usr/share/seclists`
- `/usr/share/wordlists`
- `~/wordlists`
- `~/SecLists`
- `/opt/SecLists`

---

## Usage

### Basic

```bash
python3 recon.py -d example.com
```

### Skip modules

```bash
python3 recon.py -d example.com --skip vulnscan cloud params
```

### Run only specific modules

```bash
python3 recon.py -d example.com --only subdomains dns http_probe
```

### Force screenshots on/off without prompt

```bash
python3 recon.py -d example.com --screenshots        # always on
python3 recon.py -d example.com --no-screenshots     # always off
```

### Custom output directory

```bash
python3 recon.py -d example.com --output-dir /tmp/myrecon
```

### Thread count

```bash
python3 recon.py -d example.com --threads 100
```

### Dry run (show plan, no execution)

```bash
python3 recon.py -d example.com --dry-run
```

---

## Interactive prompts

On startup the tool asks two interactive questions:

**1. Screenshots?**
```
❓  Run screenshots with gowitness? (can be slow for large scopes)
   y = yes   n = skip   Enter = skip
   › 
```

**2. nmap profile** (only if portscan is selected):
```
❓  Choose nmap scan profile:
   [1] Quick top-1000          -T4 --open -F
   [2] Full port scan          -T4 --open -p-
   [3] Stealth SYN + version   -T4 --open -sS -sV -p-
   [4] Service + script scan   -T4 --open -sV -sC -p-
   [5] Custom                  enter your own flags
   › 
```

---

## Output structure

```
~/Desktop/example.com-RECON/
├── subdomains/
│   ├── subfinder.txt
│   ├── amass.txt
│   ├── assetfinder.txt
│   └── all_subdomains.txt          ← merged + deduplicated
├── dns/
│   ├── resolved.txt                ← dnsx resolution
│   ├── bruteforce.txt              ← dnsx brute-force
│   ├── massdns.txt
│   ├── all_resolved.txt            ← merged
│   └── zone_transfer.txt           ← AXFR results (if any)
├── http_probe/
│   ├── live_urls.txt               ← httpx output with titles/status
│   ├── live_hosts.txt              ← clean base URLs for downstream
│   ├── wafw00f.txt
│   └── whatweb.txt
├── crawl/
│   ├── katana.txt
│   ├── gau.txt
│   ├── waybackurls.txt
│   └── all_urls.txt                ← merged
├── fuzzing/
│   ├── ffuf_<host>.txt
│   └── all_findings.txt
├── params/
│   └── arjun_results.json
├── portscan/
│   ├── nmap.txt
│   ├── nmap.xml
│   └── nmap.gnmap
├── vulnscan/
│   ├── nuclei_findings.txt
│   └── nuclei_findings.jsonl
├── screenshots/                    ← optional
│   ├── urls.txt
│   ├── *.png
│   └── report.html
├── secrets/
│   ├── trufflehog.json
│   ├── gitleaks.json
│   └── secrets_found.txt           ← consolidated findings
└── cloud/
    ├── cloud_<keyword>.txt
    └── cloud_findings.txt
```

---

## Architecture

```
recon/
├── recon.py              # entry point, orchestrator, interactive prompts
├── requirements.txt
├── data/
│   └── resolvers.txt     # public DNS resolvers for massdns
├── core/
│   ├── config.py         # tool registry, wordlist registry, module requirements
│   ├── console.py        # rich-based print helpers, banner
│   ├── checks.py         # preflight: tool availability + wordlist existence
│   └── runner.py         # subprocess wrapper, RunnerContext shared state
└── modules/
    ├── subdomains.py
    ├── dns.py
    ├── http_probe.py
    ├── crawl.py
    ├── fuzzing.py
    ├── params.py
    ├── portscan.py
    ├── vulnscan.py
    ├── screenshots.py
    ├── secrets.py
    └── cloud.py
```

**RunnerContext** is the shared state object passed to every module. Modules deposit their results back into it (e.g. `ctx.live_urls`, `ctx.resolved_subdomains`) so downstream modules can consume them without re-reading files.

Each module:
- Accepts `RunnerContext`, returns a `dict` summary
- Handles its own tool availability checks gracefully
- Skips cleanly with a message if tools/wordlists are missing
- Never crashes the pipeline — errors are caught at the orchestrator level

---

## Tips

- Run `--dry-run` first on a new target to review the plan and confirm all tools are present.
- For large scopes (100+ subdomains) skip screenshots initially (`--no-screenshots`) and run them separately once you've triaged.
- `nuclei` auto-updates its templates on each run. If you're offline, it will use cached templates.
- Secrets output is always written to `secrets/secrets_found.txt` even if empty, so you can grep it later.
- The `massdns` module requires `data/resolvers.txt` — a default list of public resolvers is bundled.

---

## Legal

Only run this against systems you own or have explicit written permission to test. Unauthorized scanning is illegal.
"# Recon-Tool" 
