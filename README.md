# ffuf-intel

Intelligent Python wrapper around [ffuf](https://github.com/ffuf/ffuf) with deep content inspection, adaptive HTTP probing, and optional credential testing.

> **Legal:** Use only on systems you own or have **written authorization** to test. Unauthorized access is illegal.

## Features

| Feature | Description |
|---------|-------------|
| **Native ffuf** | Runs `ffuf` with auto-calibration (`-ac`) and JSON output |
| **Deep inspection** | Async `httpx` follow-up on interesting responses |
| **Content analysis** | Internal IPs, secrets, API paths, framework fingerprints, HTML structure |
| **Adaptive HTTP** | Probes allowed methods (405), Content-Types (JSON, form, XML) |
| **Auth intelligence** | Login form + HTTP Basic detection; optional default/common cred tests |
| **Next-hop fuzzing** | Triggers (`admin`, `api`, `graphql`, `config`) spawn targeted secondary ffuf passes |
| **Intel pass** | Same-origin crawling, version fingerprints, forms, JS file harvesting, hidden endpoint mining |

## Requirements

- Python **3.10+**
- [ffuf](https://github.com/ffuf/ffuf) on `PATH`, or place binary in `tools/ffuf` (Linux/macOS) / `tools/ffuf.exe` (Windows)
- Authorized target scope

## Install

```bash
git clone https://github.com/YOUR_USER/ffuf-intel.git
cd ffuf-intel
python -m venv .venv

# Linux / macOS
source .venv/bin/activate

# Windows
.venv\Scripts\activate

pip install -r requirements.txt
pip install -e .
```

### Install ffuf

| OS | Command |
|----|---------|
| **Linux** | `sudo apt install ffuf` or [releases](https://github.com/ffuf/ffuf/releases) (`linux_amd64`) |
| **macOS** | `brew install ffuf` |
| **Windows** | Download `windows_amd64` zip (not ARM on Intel PCs) from [releases](https://github.com/ffuf/ffuf/releases) |

Verify: `ffuf -V`

## Usage

```bash
ffuf-intel -u https://target.example/FUZZ -w /path/to/wordlist.txt
```

If `FUZZ` is omitted, it is appended automatically.

### Common options

| Flag | Default | Description |
|------|---------|-------------|
| `--ffuf-path` | PATH lookup | Explicit path to ffuf binary |
| `--aggression` | `A2` | Aggression preset: `A1` to `A4` |
| `--max-depth` | preset-based | Override recursive reasoning depth |
| `--concurrency` | `20` | Parallel inspection requests |
| `--timeout` | `15` | Inspection HTTP timeout (seconds) |
| `--no-adaptive` | off | Disable method/Content-Type probing |
| `--fuzz-modes` | `path,query,header` | Secondary fuzz modes: `path`, `query`, `header`, `body` |
| `--all-wordlists` | off | Use every bundled wordlist for secondary passes |
| `--no-result-threshold` | preset-based | Prompt after this many zero-result passes |
| `--continue-without-ask` | off | Continue automatically when the threshold is reached |
| `--output-dir` | `ffuf-intel-output/` | Directory where JSON and Markdown reports are written |
| `--auth-policy` | `ask` | Credential testing: `off`, `ask`, `defaults`, `common`, `unrestricted` |
| `--intel` | off | Crawl same-origin pages and mine technology versions + JavaScript endpoints |
| `--crawl-depth` | `2` | Maximum depth for the `--intel` crawler |
| `--crawl-pages` | `100` | Maximum pages for the `--intel` crawler |
| `--probe-js-endpoints` | off | Actively probe same-origin endpoints found in JavaScript |
| `-v` | off | Verbose output |

### Examples

```bash
# Basic scan
ffuf-intel -u https://target.example/FUZZ -w wordlists/common.txt

# Extra ffuf flags (after --)
ffuf-intel -u https://target.example/FUZZ -w dirs.txt -- -rate 50 -t 30

# Detect login/Basic only (no password attempts)
ffuf-intel -u https://target.example/FUZZ -w admin.txt --auth-policy off

# Auto-try default credentials (authorized labs only)
ffuf-intel -u https://target.example/FUZZ -w admin.txt --auth-policy defaults

# More aggressive full sweep
ffuf-intel -u https://target.example/FUZZ -w wordlists/common.txt --aggression A4 --all-wordlists

# Add crawler, version detection, and JS hidden endpoint discovery
ffuf-intel -u https://target.example/FUZZ -w wordlists/common.txt --intel

# Also probe discovered same-origin JS endpoints
ffuf-intel -u https://target.example/FUZZ -w wordlists/common.txt --intel --probe-js-endpoints

# Keep going automatically after zero-result streaks
ffuf-intel -u https://target.example/FUZZ -w wordlists/common.txt --no-result-threshold 3 --continue-without-ask
```

## Intelligence pass

`--intel` adds a safe, same-origin discovery layer before the ffuf campaign:

- Crawls HTML pages up to `--crawl-depth` / `--crawl-pages`
- Extracts forms, linked JavaScript files, and inline scripts
- Fingerprints server headers, generator tags, CMS/framework markers, and JavaScript library versions
- Mines JavaScript for hidden API paths, GraphQL/auth/admin endpoints, URL parameters, and high-signal secret patterns
- Writes structured results to `report.json` under `intel` and summarizes them in `report.md`

Endpoint probing is disabled by default. Use `--probe-js-endpoints` only when the target is explicitly in scope; probes are constrained to the same origin as the target URL.

## Auth policies

| Policy | Behavior |
|--------|----------|
| `off` | Detect login forms / Basic Auth only |
| `ask` | Prompt once before any credential attempts |
| `defaults` | Small built-in pairs (`admin:admin`, etc.) |
| `common` | Defaults + bundled common-password list (capped) |
| `unrestricted` | Higher attempt cap, no prompt |

Wordlists: `ffuf_intel/wordlists/default_users.txt`, `common_passwords.txt`

## How it works

1. **ffuf pass** — fuzz with `-ac`, parse JSON for interesting status codes.
2. **Inspection** — fetch each hit; analyze body/headers; adaptive method/body negotiation.
3. **Auth probe** (if enabled) — forms, Basic Auth, optional cred tests.
4. **Reasoning** — triggers queue nested ffuf on `{url}/FUZZ` with specialized wordlists.
5. **Reuse** — successful auth (Basic/Cookie) applied to later requests on the same host.

## Project layout

```
ffuf-intel/
├── ffuf_intel/
│   ├── cli.py              # CLI entry
│   ├── crawler.py          # Same-origin crawl, JS/form harvesting
│   ├── version_detect.py   # Header/HTML/JS version fingerprints
│   ├── js_miner.py         # Hidden JS endpoint and secret-pattern discovery
│   ├── ffuf_runner.py      # subprocess ffuf
│   ├── inspector.py        # async deep inspection
│   ├── adaptive.py         # method / Content-Type probing
│   ├── auth_probe.py       # login form & Basic Auth
│   ├── auth_policy.py      # consent & limits
│   ├── reasoning.py        # recursive next-hop
│   ├── patterns.py         # detection regex
│   └── wordlists/          # trigger & auth wordlists
├── scripts/
│   ├── clean_repo.sh       # remove venv/artifacts before git push
│   └── clean_repo.ps1
├── tools/                  # optional local ffuf binary (gitignored)
├── pyproject.toml
├── requirements.txt
├── LICENSE
└── README.md
```

## Clean before Git push

Remove virtualenv and build artifacts (never commit `.venv`):

```powershell
# Windows
powershell -ExecutionPolicy Bypass -File scripts\clean_repo.ps1
```

```bash
# Linux / macOS
chmod +x scripts/clean_repo.sh && ./scripts/clean_repo.sh
```

## Publish to GitHub

```bash
git init
git add .
git commit -m "Initial commit: ffuf-intel intelligent wrapper"
git branch -M main
git remote add origin https://github.com/YOUR_USER/ffuf-intel.git
git push -u origin main
```

## Disclaimer

This tool is for **authorized security testing and education** only. The authors are not responsible for misuse. Always obtain permission before scanning or attempting credentials.

## Credits

This tool is built on top of ffuf and would not be possible without the work of the ffuf contributors:
https://github.com/ffuf/ffuf

## License

MIT — see [LICENSE](LICENSE).
