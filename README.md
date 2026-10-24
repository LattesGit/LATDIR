# LATENTDIR

**A lightweight, concurrent web-path discovery tool for authorized security testing.**

LATENTDIR checks paths from a user-provided wordlist, reports selected HTTP status codes as results arrive, displays scan progress, and writes a JSON report for later review. It is designed for controlled testing of systems you own or have explicit permission to assess.

> **Authorization required:** Only scan systems you own or have explicit written permission to test. You are responsible for complying with applicable laws, policies, and the target's rules of engagement.

## Features

- Concurrent HTTP requests with a bounded in-flight task queue
- Live findings and terminal progress display
- Configurable status-code filtering, timeout, delay, worker count, and extensions
- Heuristic wildcard-response check using bounded response samples
- JSON report with queued/completed counts, request errors, and interruption state
- Partial report saved after an ordinary `Ctrl+C` during the scan
- Input validation for targets, wordlist entries, extensions, and CLI values
- Standalone `main.py` so the tool can be inspected and run without installing the package

## Requirements

- Python 3.10 or newer
- `requests`

## Installation

```bash
git clone https://github.com/YOUR-USERNAME/LATENTDIR.git
cd LATENTDIR
python -m pip install -r requirements.txt
```

Replace `YOUR-USERNAME` with the GitHub account that hosts the repository.

## Quick start

Use a target you are authorized to test:

```bash
python main.py --url http://127.0.0.1:8000 --wordlist wordlist.txt --authorized
```

Set concurrency, timeout, extensions, and output path:

```bash
python main.py \
  --url http://127.0.0.1:8000 \
  --wordlist wordlist.txt \
  --threads 20 \
  --timeout 5 \
  --extensions php,txt,html \
  --status-codes 200,204,301,302,307,308,401,403 \
  --output reports/local-test.json \
  --authorized
```

On Windows PowerShell, enter the command on one line or use PowerShell's backtick for line continuation.

## Command-line options

| Option | Default | Description |
|---|---:|---|
| `-u`, `--url` | Required | Target base URL (`http://` or `https://`) |
| `-w`, `--wordlist` | Required | Path to a newline-separated wordlist |
| `-t`, `--threads` | `30` | Concurrent workers, from 1 to 50 |
| `--timeout` | `5.0` | Request timeout in seconds |
| `-x`, `--extensions` | None | Comma-separated file extensions, e.g. `php,txt` |
| `-s`, `--status-codes` | Common success/redirect/auth codes | Comma-separated HTTP status codes |
| `-o`, `--output` | `reports/latest.json` | JSON report output path |
| `--delay` | `0.0` | Delay before each request, in seconds |
| `--no-color` | Off | Disable terminal colors |
| `--authorized` | Required | Confirm authorization to test the target |
| `--version` | — | Print the current version |

## Wordlist format

Use one relative path per line. Blank lines and lines beginning with `#` are ignored; duplicate entries are removed. Absolute URLs, query strings, fragments, backslashes, and dot-segment traversal entries are rejected.

```text
# Common application paths
admin
api
assets
package.json
robots.txt
```

## Output

By default, results are saved to `reports/latest.json`. The report includes:

- Target URL and UTC timestamp
- Number of paths queued and completed
- Number of findings and request errors
- Whether the scan was interrupted
- Finding URLs, status codes, reported content lengths, elapsed times, and request errors where applicable

A content length of `-1` means the server did not provide a usable `Content-Length` header; it does not necessarily mean the response body is empty. The wildcard check is heuristic and can produce false positives or false negatives.

## Development and testing

```bash
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```

The tests cover URL validation, wordlist parsing, path construction, and basic result filtering. They do not replace testing against a controlled local HTTP server.

## Limitations

- This is a path-discovery utility, not a full web vulnerability scanner.
- A listed status code does not prove that a path is sensitive or exploitable.
- Redirects are recorded but not followed.
- The wildcard detector compares a limited sample of response bodies and is only a heuristic.
- On interruption, completed findings are written to the report; requests already running may take up to their configured timeout to exit.

## License

Released under the MIT License. See [`LICENSE`](LICENSE).
