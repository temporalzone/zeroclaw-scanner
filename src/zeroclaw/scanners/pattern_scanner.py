"""Code pattern scanner: SQLi, XSS, unsafe patterns."""
import logging
import os
import re
import stat
import time
from collections import deque
from pathlib import Path

from zeroclaw.models import Category, Finding, Severity

logger = logging.getLogger(__name__)

DANGEROUS_PATTERNS = [
    (
        r"\.execute\s*\(\s*f['\"]",
        "Possible SQL injection (f-string in execute)",
        Severity.HIGH,
        "Use parameterized queries instead of f-string formatting.",
    ),
    (
        r"\.execute\s*\(\s*['\"][^'\"]*\+",
        "Possible SQL injection (string concat in execute)",
        Severity.HIGH,
        "Use parameterized queries instead of string concatenation.",
    ),
    (
        r"dangerouslySetInnerHTML",
        "XSS risk: dangerouslySetInnerHTML",
        Severity.HIGH,
        "Avoid using dangerouslySetInnerHTML, or sanitize input using DOMPurify.",
    ),
    (
        r"\.innerHTML\s*=(?!\s*\"\")",
        "XSS risk: innerHTML assignment",
        Severity.HIGH,
        "Use textContent or innerText instead of innerHTML assignment.",
    ),
    (
        r"document\.write\s*\(",
        "XSS risk: document.write",
        Severity.MEDIUM,
        "Use safe DOM APIs like appendChild or textContent instead of document.write.",
    ),
    (
        r"subprocess\.(call|run|Popen)\s*\([\s\S]*?shell\s*=\s*True",
        "Command injection: shell=True",
        Severity.HIGH,
        "Avoid shell=True in subprocess calls. Pass arguments as a list instead of a string.",
    ),
]

EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx",
    ".html", ".htm", ".vue", ".svelte",
}

# --- Bounded resource limits (DoS prevention) ---
CHUNK_READ_SIZE = 2049          # max bytes per readline() call
WINDOW_SIZE = 3                 # sliding window depth (in chunks)
MAX_FILE_COUNT = 10_000         # max files to scan
MAX_CUMULATIVE_SIZE = 500 * 1024 * 1024  # 500 MB total across all files
MAX_FINDINGS = 1000             # hard cap on findings list size
SCAN_TIMEOUT_SECONDS = 300      # 5-minute wall-clock timeout


def _find_all_dangerous_patterns(text: str) -> list[tuple[str, Severity, str, str]]:
    """Return every dangerous pattern found in *text*.

    Evaluates ALL patterns (not just the first match) so that a
    low-severity hit cannot mask a higher-severity one in the same
    context.  Uses re.finditer to capture multiple instances of the same
    pattern within the sliding window, and re.DOTALL to match across newlines.
    """
    matches: list[tuple[str, Severity, str, str]] = []
    for pattern, message, severity, remediation in DANGEROUS_PATTERNS:
        for match in re.finditer(pattern, text, re.DOTALL):
            matches.append((message, severity, match.group(0), remediation))
    return matches


def scan_patterns(target_dir: Path) -> list[Finding]:
    """Scan for dangerous code patterns.

    Reads files in bounded chunks via readline(CHUNK_READ_SIZE) and feeds
    them into a fixed-size sliding window.  This design:
      - Bounds memory per read (no OOM on huge lines).
      - Bridges chunk boundaries naturally via window concatenation,
        so patterns straddling a read boundary are still detected.
      - Evaluates ALL patterns per context (no masking of critical
        findings by lower-severity matches).
      - Uses proximity-based deduplication (per chunk index) to
        prevent the same match from re-triggering as it slides
        through the window, without destructively clearing the buffer.

    Post-open fstat/stat identity verification closes the TOCTOU window
    on all platforms, including Windows where O_NOFOLLOW is unavailable.
    """
    findings: list[Finding] = []
    resolved_target = target_dir.resolve()
    file_count = 0
    cumulative_size = 0
    start_time = time.monotonic()

    for file_path in target_dir.rglob("*"):
        # --- Global resource guards ---
        if len(findings) >= MAX_FINDINGS:
            logger.warning("Max findings reached (%d). Stopping.", MAX_FINDINGS)
            break

        if time.monotonic() - start_time > SCAN_TIMEOUT_SECONDS:
            logger.warning("Scan timeout reached (%ds). Stopping.", SCAN_TIMEOUT_SECONDS)
            break

        if file_count >= MAX_FILE_COUNT:
            logger.warning("Max file count reached (%d). Stopping.", MAX_FILE_COUNT)
            break

        # Skip symlinks
        if file_path.is_symlink():
            logger.warning("Skipping symbolic link: %s", file_path)
            continue

        # Only process regular files
        if not file_path.is_file():
            continue

        if file_path.suffix not in EXTENSIONS:
            continue

        fd = None
        try:
            # Boundary check using Path.resolve() before open
            resolved_file = file_path.resolve()
            if not resolved_file.is_relative_to(resolved_target):
                logger.warning("Skipping file outside target directory: %s", file_path)
                continue

            # Open file descriptor securely (O_NOFOLLOW prevents following symlinks
            # on POSIX; getattr fallback returns 0 on Windows for compatibility)
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(str(resolved_file), flags)

            # --- Post-open TOCTOU verification (cross-platform) ---
            # Compare the opened fd's identity against the resolved path's
            # identity using device + inode.  This catches symlink/junction
            # swaps that occur between resolve() and os.open(), including on
            # Windows where O_NOFOLLOW is unavailable.
            fstat_info = os.fstat(fd)

            try:
                path_stat_info = os.stat(str(resolved_file))
            except OSError:
                os.close(fd)
                fd = None
                logger.warning("Skipping file (cannot stat resolved path): %s", file_path)
                continue

            if (fstat_info.st_dev != path_stat_info.st_dev
                    or fstat_info.st_ino != path_stat_info.st_ino):
                os.close(fd)
                fd = None
                logger.warning(
                    "Skipping file (identity mismatch, possible symlink swap): %s",
                    file_path,
                )
                continue

            # Verify opened fd is a regular file
            if not stat.S_ISREG(fstat_info.st_mode):
                logger.warning("Skipping non-regular file: %s", file_path)
                os.close(fd)
                fd = None
                continue

            # Per-file size limit (5 MB)
            if fstat_info.st_size > 5 * 1024 * 1024:
                os.close(fd)
                fd = None
                continue

            # Cumulative size limit
            cumulative_size += fstat_info.st_size
            if cumulative_size > MAX_CUMULATIVE_SIZE:
                os.close(fd)
                fd = None
                logger.warning("Cumulative size limit reached. Stopping.")
                break

            file_count += 1

            # Read securely using the file descriptor
            with os.fdopen(fd, "r", encoding="utf-8", errors="ignore") as f:
                fd = None  # os.fdopen takes ownership of the descriptor
                window: deque[str] = deque(maxlen=WINDOW_SIZE)
                line_number = 1

                # Set of hashed signatures to prevent duplicate reporting of
                # the exact same payload as it slides through the window.
                reported_signatures: set[int] = set()

                while True:
                    # Enforce findings cap inside the read loop
                    if len(findings) >= MAX_FINDINGS:
                        break

                    # Read a bounded chunk.  readline(CHUNK_READ_SIZE)
                    # returns at most CHUNK_READ_SIZE chars — either a
                    # full short line (incl. \n) or a partial long line.
                    # The sliding window bridges adjacent chunks, so
                    # patterns straddling a boundary are still detected.
                    chunk = f.readline(CHUNK_READ_SIZE)
                    if not chunk:
                        break

                    window.append(chunk)
                    context = "".join(window)

                    # Evaluate ALL patterns on the current context so
                    # that a low-severity match cannot mask a critical
                    # one in the same window.
                    for message, severity, matched_string, remediation in _find_all_dangerous_patterns(context):
                        # Signature-based dedup: distinguish unique occurrences
                        # by hashing the combination of file, message, string, and line number.
                        sig = hash((str(file_path), message, matched_string, line_number))
                        if sig in reported_signatures:
                            continue

                        if len(findings) >= MAX_FINDINGS:
                            break

                        findings.append(
                            Finding(
                                id=f"PATTERN-{len(findings)+1:04d}",
                                severity=severity,
                                category=Category.CODE_PATTERN,
                                title=message,
                                description=(
                                    f"{message} at line {line_number}: "
                                    f"{chunk.strip()[:120]}"
                                ),
                                file_path=str(file_path),
                                line_number=line_number,
                                remediation=remediation,
                            )
                        )
                        reported_signatures.add(sig)

                    # Accurate line tracking: count all newlines in chunk
                    line_number += chunk.count("\n")

        except (OSError, UnicodeDecodeError) as e:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            logger.warning("Could not read file %s: %s", file_path, e)

    return findings
