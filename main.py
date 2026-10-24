from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import math
import secrets
import sys
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit

import requests

VERSION = "0.6.0" # It will be updating
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
SPINNER_FRAMES = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
DEFAULT_STATUS_CODES = {200, 204, 301, 302, 307, 308, 401, 403}

_thread_local = threading.local()
_print_lock = threading.Lock()


@dataclass(frozen=True, slots=True)
class ScanResult:
    url: str
    status_code: int
    content_length: int
    elapsed_ms: float
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def color(text: str, shade: str, enabled: bool = True) -> str:
    return f"{shade}{text}{RESET}" if enabled else text


def validate_target(target: str) -> str:
    target = target.strip()
    if not target:
        raise ValueError("Target URL cannot be empty.")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in target):
        raise ValueError("Target URL contains control characters.")
    if any(ch.isspace() for ch in target):
        raise ValueError("Target URL must not contain whitespace.")
    if "\\" in target:
        raise ValueError("Backslashes are not allowed in target URLs.")
    if "?" in target or "#" in target:
        raise ValueError("Target URL must not contain a query or fragment.")

    try:
        parsed = urlsplit(target)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Target URL is malformed.") from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Target must start with http:// or https://.")
    if not parsed.netloc or not hostname:
        raise ValueError("A valid hostname is required.")
    if any(ch.isspace() for ch in hostname):
        raise ValueError("Target hostname contains whitespace.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Credentials are not allowed in target URLs.")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Target port must be between 1 and 65535.")

    return target.rstrip("/") + "/"


def load_wordlist(filename: str) -> list[str]:
    path = Path(filename)
    if not path.is_file():
        raise FileNotFoundError(f"Wordlist not found: {filename}")

    raw = path.read_bytes()
    if not raw:
        raise ValueError("Wordlist is empty.")

    encodings = ("utf-16", "utf-8-sig", "cp1252", "latin-1") if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else ("utf-8-sig", "cp1252", "latin-1")
    text = None
    for encoding in encodings:
        try:
            text = raw.decode(encoding)
            break
        except UnicodeError:
            continue
    if text is None:
        raise ValueError("Unable to decode wordlist.")

    words: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        word = line.strip().lstrip("/")
        if not word or word.startswith("#"):
            continue
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in word):
            continue
        if "://" in word or "\\" in word or "?" in word or "#" in word:
            continue
        if any(segment in {".", ".."} for segment in word.split("/")):
            continue
        if word not in seen:
            seen.add(word)
            words.append(word)

    if not words:
        raise ValueError("Wordlist contains no usable paths.")
    return words


def get_session() -> requests.Session:
    session = getattr(_thread_local, "session", None)
    if session is None:
        session = requests.Session()
        session.headers.update({"User-Agent": f"LATENTDIR/{VERSION} (authorized testing)"})
        _thread_local.session = session
    return session


def build_url(base_url: str, path: str) -> str:
    relative_path = path.lstrip("/")
    if not relative_path or any(segment in {".", ".."} for segment in relative_path.split("/")):
        raise ValueError("Invalid relative path.")
    if any(ch in relative_path for ch in "\\?#") or "://" in relative_path:
        raise ValueError("Wordlist entries must be relative paths.")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in relative_path):
        raise ValueError("Relative path contains control characters.")

    encoded_path = quote(relative_path, safe="/:@!$&'()*+,;=-._~")
    return base_url + encoded_path


def content_length(response: requests.Response) -> int:
    raw = response.headers.get("Content-Length", "")
    return int(raw) if raw.isascii() and raw.isdigit() else -1


def request_url(url: str, timeout: float) -> ScanResult:
    started = time.perf_counter()
    try:
        response = get_session().get(
            url,
            timeout=timeout,
            allow_redirects=False,
            stream=True,
        )
        try:
            return ScanResult(
                url=url,
                status_code=response.status_code,
                content_length=content_length(response),
                elapsed_ms=round((time.perf_counter() - started) * 1000, 2),
            )
        finally:
            response.close()
    except requests.RequestException as exc:
        return ScanResult(
            url=url,
            status_code=0,
            content_length=-1,
            elapsed_ms=round((time.perf_counter() - started) * 1000, 2),
            error=type(exc).__name__,
        )


def is_interesting(result: ScanResult, status_codes: set[int]) -> bool:
    return result.error is None and result.status_code in status_codes


def response_signature(url: str, timeout: float, max_bytes: int = 65536) -> tuple[int, int, str] | None:
    if max_bytes < 1:
        raise ValueError("max_bytes must be positive.")

    try:
        with get_session().get(
            url,
            timeout=timeout,
            allow_redirects=False,
            stream=True,
        ) as response:
            digest = hashlib.sha256()
            consumed = 0
            for chunk in response.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                piece = chunk[: max_bytes - consumed]
                digest.update(piece)
                consumed += len(piece)
                if consumed >= max_bytes:
                    break
            return response.status_code, content_length(response), digest.hexdigest()
    except requests.RequestException:
        return None


def wildcard_probe(
    base_url: str,
    timeout: float,
    use_color: bool = True,
    interactive: bool = True,
) -> list[tuple[int, int, str]]:
    urls = [build_url(base_url, "__latentdir_probe_" + secrets.token_hex(12)) for _ in range(3)]
    samples: list[tuple[int, int, str]] = []
    frame = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=3, thread_name_prefix="probe") as executor:
        futures = [executor.submit(response_signature, url, timeout) for url in urls]
        pending = set(futures)
        while pending:
            finished, pending = concurrent.futures.wait(
                pending,
                timeout=0.08,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            if interactive:
                spinner = SPINNER_FRAMES[frame % len(SPINNER_FRAMES)]
                completed = len(futures) - len(pending)
                line = f"{color(spinner, CYAN, use_color)} Checking wildcard behavior... {completed}/3"
                with _print_lock:
                    print("\r" + line + "\033[K", end="", flush=True)
                frame += 1

        for future in futures:
            try:
                signature = future.result()
            except Exception:
                signature = None
            if signature is not None:
                samples.append(signature)

    if interactive:
        with _print_lock:
            print("\r\033[K", end="", flush=True)
    return samples


def print_live_result(result: ScanResult, use_color: bool = True, interactive: bool = True) -> None:
    code = result.status_code
    if 200 <= code < 300:
        shade = GREEN
    elif 300 <= code < 400 or code in {401, 403}:
        shade = YELLOW
    else:
        shade = RED

    size = f"{result.content_length} B" if result.content_length >= 0 else "unknown"
    line = f"[FOUND] {color(f'[{code}]', shade, use_color)} [{size:>10}] [{result.elapsed_ms:8.2f} ms] {result.url}"
    with _print_lock:
        if interactive:
            print("\r\033[K", end="")
        print(line, flush=True)


def render_progress(
    done: int,
    total: int,
    started: float,
    found: int,
    errors: int,
    frame: int,
    use_color: bool = True,
    interactive: bool = True,
) -> None:
    width = 24
    fraction = done / total if total else 1.0
    filled = int(width * fraction)
    bar = "█" * filled + "░" * (width - filled)
    elapsed = time.perf_counter() - started
    percent = fraction * 100

    if interactive:
        spinner = SPINNER_FRAMES[frame % len(SPINNER_FRAMES)]
        line = (
            f"{color(spinner, CYAN, use_color)} [{bar}] {percent:6.2f}% "
            f"{done}/{total} Found: {found} Errors: {errors} {elapsed:5.1f}s"
        )
        with _print_lock:
            print("\r" + line + "\033[K", end="", flush=True)
        return

    checkpoint = max(1, math.ceil(total / 20))
    if done % checkpoint == 0 or done == total:
        with _print_lock:
            print(
                f"Progress: {percent:6.2f}% {done}/{total} | Found: {found} "
                f"| Errors: {errors} | {elapsed:.1f}s",
                flush=True,
            )


def build_paths(words: list[str], extensions: list[str]) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()
    for word in words:
        for candidate in (word, *(f"{word}.{ext}" for ext in extensions)):
            if candidate not in seen:
                seen.add(candidate)
                paths.append(candidate)
    return paths


def scan(
    base_url: str,
    words: list[str],
    workers: int,
    timeout: float,
    status_codes: set[int],
    extensions: list[str],
    delay: float,
    use_color: bool = True,
) -> tuple[list[ScanResult], int, int, int, bool]:
    paths = build_paths(words, extensions)
    total = len(paths)
    results: list[ScanResult] = []
    errors = completed = 0
    started = time.perf_counter()
    interactive = sys.stdout.isatty()
    interrupted = False
    stop_event = threading.Event()

    def task(path: str) -> ScanResult:
        if delay and stop_event.wait(delay):
            return ScanResult(build_url(base_url, path), 0, -1, 0.0, "Interrupted")
        return request_url(build_url(base_url, path), timeout)

    print(f"Target: {base_url}")
    print(f"Paths queued: {total} | Workers: {workers}")
    print("Extensions: " + (", ".join(extensions) if extensions else "None"))
    print("Scan started...")
    print("=" * 72)

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="latentdir")
    path_iterator = iter(paths)
    pending: dict[concurrent.futures.Future[ScanResult], str] = {}
    queue_limit = max(workers, workers * 3)
    frame = 0

    try:
        while True:
            while len(pending) < queue_limit:
                try:
                    path = next(path_iterator)
                except StopIteration:
                    break
                pending[executor.submit(task, path)] = path

            if not pending:
                break

            finished, _ = concurrent.futures.wait(
                pending,
                timeout=0.08,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            for future in finished:
                pending.pop(future, None)
                completed += 1
                try:
                    result = future.result()
                except concurrent.futures.CancelledError:
                    continue
                except Exception:
                    errors += 1
                    continue

                if result.error:
                    errors += 1
                elif is_interesting(result, status_codes):
                    results.append(result)
                    print_live_result(result, use_color, interactive)

            render_progress(completed, total, started, len(results), errors, frame, use_color, interactive)
            frame += 1

    except KeyboardInterrupt:
        interrupted = True
        stop_event.set()
        for future in pending:
            future.cancel()
        print("\n[!] Interrupt received. Saving completed findings...", flush=True)
    finally:
        if interrupted:
            stop_event.set()
            for future in pending:
                future.cancel()
        executor.shutdown(wait=True, cancel_futures=interrupted)
        if interrupted:
            for future in pending:
                if future.cancelled():
                    continue
                try:
                    result = future.result()
                except concurrent.futures.CancelledError:
                    continue
                except Exception:
                    completed += 1
                    errors += 1
                    continue
                completed += 1
                if result.error:
                    errors += 1
                elif is_interesting(result, status_codes):
                    results.append(result)
                    print_live_result(result, use_color, interactive)
        if interactive:
            with _print_lock:
                print("\r\033[K", end="", flush=True)

    return sorted(results, key=lambda item: item.url), total, errors, completed, interrupted


def save_report(
    results: list[ScanResult],
    output: str,
    target: str,
    total_paths: int,
    completed_paths: int,
    errors: int,
    interrupted: bool,
) -> None:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "tool": "LATENTDIR",
        "version": VERSION,
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "paths_queued": total_paths,
        "paths_completed": completed_paths,
        "findings_count": len(results),
        "request_errors": errors,
        "interrupted": interrupted,
        "findings": [result.to_dict() for result in results],
    }
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    temporary.replace(path)


def parse_status_codes(value: str) -> set[int]:
    raw_codes = [item.strip() for item in value.split(",")]
    if not raw_codes or any(not item for item in raw_codes):
        raise ValueError("Provide comma-separated HTTP status codes.")
    try:
        status_codes = {int(item) for item in raw_codes}
    except ValueError as exc:
        raise ValueError("HTTP status codes must contain numbers only.") from exc
    if not status_codes or any(code < 100 or code > 599 for code in status_codes):
        raise ValueError("HTTP status codes must be between 100 and 599.")
    return status_codes


def parse_extensions(value: str) -> list[str]:
    raw_extensions = [item.strip() for item in value.split(",") if item.strip()]
    extensions = [item.lstrip(".") for item in raw_extensions]
    for ext in extensions:
        if (
            not ext
            or any(ch in ext for ch in "/\\?#:%")
            or any(ch.isspace() for ch in ext)
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in ext)
            or ext in {".", ".."}
        ):
            raise ValueError(f"Invalid file extension: {ext!r}")
    return list(dict.fromkeys(extensions))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Discover web paths on an authorized target.")
    parser.add_argument("-u", "--url", required=True, help="Authorized target URL")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to the wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=30, help="Concurrent workers (1-50)")
    parser.add_argument("--timeout", type=float, default=5.0, help="Request timeout in seconds")
    parser.add_argument("-x", "--extensions", default="", help="Comma-separated extensions, e.g. php,txt,html")
    parser.add_argument(
        "-s",
        "--status-codes",
        default=",".join(str(code) for code in sorted(DEFAULT_STATUS_CODES)),
        help="Comma-separated HTTP status codes",
    )
    parser.add_argument("-o", "--output", default="reports/latest.json", help="JSON report path")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay before each request, in seconds")
    parser.add_argument("--no-color", action="store_true", help="Disable terminal colors")
    parser.add_argument("--authorized", action="store_true", help="Confirm permission to test the target")
    parser.add_argument("--version", action="version", version=VERSION)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    use_color = not args.no_color and sys.stdout.isatty()

    if not args.authorized:
        print("[!] Use --authorized to confirm permission.", file=sys.stderr)
        return 2
    if not 1 <= args.threads <= 50:
        print("[!] Workers must be between 1 and 50.", file=sys.stderr)
        return 2
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        print("[!] Timeout must be finite and positive.", file=sys.stderr)
        return 2
    if not math.isfinite(args.delay) or args.delay < 0:
        print("[!] Delay must be finite and non-negative.", file=sys.stderr)
        return 2

    run_started = time.perf_counter()
    target = ""
    results: list[ScanResult] = []
    total_paths = completed_paths = errors = 0
    interrupted = False

    try:
        target = validate_target(args.url)
        wordlist_path = Path(args.wordlist).resolve()
        output_path = Path(args.output).resolve()
        script_path = Path(__file__).resolve()
        if output_path in {wordlist_path, script_path}:
            raise ValueError("Report path must not overwrite the wordlist or the running script.")
        words = load_wordlist(args.wordlist)
        status_codes = parse_status_codes(args.status_codes)
        extensions = parse_extensions(args.extensions)

        print(color("Wordlist loaded:", CYAN, use_color), f"{len(words)} entries")
        print(color("Checking random paths for wildcard responses...", CYAN, use_color))
        samples = wildcard_probe(target, args.timeout, use_color, sys.stdout.isatty())
        if len(samples) == 3 and len(set(samples)) == 1:
            print(color(
                "[!] Random paths returned matching response fingerprints. Wildcard routing may be enabled.",
                YELLOW,
                use_color,
            ))
        elif len(samples) < 3:
            print(color("[!] Wildcard check was inconclusive (some probes failed).", YELLOW, use_color))

        results, total_paths, errors, completed_paths, interrupted = scan(
            target,
            words,
            args.threads,
            args.timeout,
            status_codes,
            extensions,
            args.delay,
            use_color,
        )
        save_report(results, args.output, target, total_paths, completed_paths, errors, interrupted)
        print("\n" + color("Scan summary", GREEN, use_color))
        print(f"Paths queued  : {total_paths}")
        print(f"Paths completed: {completed_paths}")
        print(f"Findings      : {len(results)}")
        print(f"Request errors: {errors}")
        print(f"Report        : {args.output}")
        print(color(f"Elapsed       : {time.perf_counter() - run_started:.2f}s", GREEN, use_color))
        return 130 if interrupted else 0

    except KeyboardInterrupt:
        if target:
            try:
                save_report(results, args.output, target, total_paths, completed_paths, errors, True)
                print(f"\n[!] Partial report saved: {args.output}", file=sys.stderr)
            except OSError as exc:
                print(f"[!] Could not save partial report: {exc}", file=sys.stderr)
        print("\n[!] Scan interrupted.", file=sys.stderr)
        return 130
    except (ValueError, FileNotFoundError, OSError, requests.RequestException) as exc:
        print(color(f"[!] Error: {exc}", RED, use_color), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
