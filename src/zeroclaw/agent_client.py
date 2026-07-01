"""ZeroClaw Agent Client — bridge between Python scanners and the Rust agent.

Adapted from QA_Agent/auditor.py. Sends raw scanner findings to the locally-
installed ZeroClaw Rust binary for AI-powered reasoning and remediation.
Falls back gracefully when the agent is unavailable.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path

from .models import Finding

logger = logging.getLogger(__name__)

# Maximum seconds to wait for the Rust agent per finding
_AGENT_TIMEOUT_SECONDS = 60

# Maximum bytes of source code context to send (prevents massive prompts and Windows command-line limits)
_MAX_CONTEXT_BYTES = 6_000  # ~6 KB

# Default agent alias — must match [agents.<alias>] in ~/.zeroclaw/config.toml
_DEFAULT_AGENT_ALIAS = "scanner"

# Environment variable to override the agent alias
_AGENT_ALIAS_ENV = "ZEROCLAW_AGENT_ALIAS"

# Environment variable to override the binary path
_BINARY_PATH_ENV = "ZEROCLAW_BINARY"


def _find_zeroclaw_binary() -> str | None:
    """Locate the ZeroClaw Rust binary on the system.

    Search order:
      1. ZEROCLAW_BINARY environment variable (explicit override)
      2. PATH via shutil.which() (covers standard installs)
      3. ~/.cargo/bin/zeroclaw (Rust/cargo install default)
      4. ~/.local/share/zeroclaw/zeroclaw (install.sh default)
    """
    # 1. Env var override
    env_path = os.environ.get(_BINARY_PATH_ENV)
    if env_path:
        p = Path(env_path)
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
        logger.warning("ZEROCLAW_BINARY=%s is not a valid executable", env_path)

    # 2. Standard PATH lookup
    which_result = shutil.which("zeroclaw")
    if which_result:
        # Verify that the found command is actually the Rust agent and not the Python CLI script wrapper.
        # The Python CLI script only supports {scan, report} and lacks the 'agent' subcommand.
        try:
            res = subprocess.run([which_result, "-h"], capture_output=True, text=True, timeout=2)
            # The Rust agent binary help output will mention the 'agent' command.
            if "agent" in res.stdout or "agent" in res.stderr:
                return which_result
            else:
                logger.warning("Found 'zeroclaw' on PATH, but it lacks 'agent' subcommand support (likely the Python scanner CLI). Skipping.")
        except Exception as e:
            logger.warning("Could not execute 'zeroclaw' found on PATH for verification: %s", e)

    # 3. Cargo install default
    cargo_name = "zeroclaw.exe" if os.name == "nt" else "zeroclaw"
    cargo_path = Path.home() / ".cargo" / "bin" / cargo_name
    if cargo_path.is_file() and os.access(cargo_path, os.X_OK):
        return str(cargo_path)

    # 4. Install script default
    local_name = "zeroclaw.exe" if os.name == "nt" else "zeroclaw"
    local_path = Path.home() / ".local" / "share" / "zeroclaw" / local_name
    if local_path.is_file() and os.access(local_path, os.X_OK):
        return str(local_path)

    return None


class ZeroClawClient:
    """Sends findings to the ZeroClaw Rust agent for AI enrichment."""

    def __init__(self, agent_alias: str | None = None) -> None:
        prompt_path = Path(__file__).parent / "prompts" / "remediation.txt"
        try:
            self.system_prompt = prompt_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            logger.warning("Prompt template not found at %s — using inline fallback", prompt_path)
            self.system_prompt = (
                "You are a security remediation engine. Analyze the vulnerability "
                "and respond in JSON with 'reasoning_chain' and 'fixed_code' fields."
            )

        # Resolve agent alias
        self.agent_alias = (
            agent_alias
            or os.environ.get(_AGENT_ALIAS_ENV)
            or _DEFAULT_AGENT_ALIAS
        )

        # Resolve binary path once at init
        self._binary = _find_zeroclaw_binary()
        if self._binary:
            logger.info("ZeroClaw binary found at: %s", self._binary)
        else:
            logger.warning(
                "ZeroClaw binary not found in PATH, ~/.cargo/bin, or "
                "~/.local/share/zeroclaw. Set %s to override.",
                _BINARY_PATH_ENV,
            )

    @property
    def is_available(self) -> bool:
        """Check if the ZeroClaw binary was found during init."""
        return self._binary is not None

    def enrich_finding(self, finding: Finding, file_path: Path, raise_on_error: bool = False) -> Finding:
        """Send a raw finding to the ZeroClaw Rust Agent for remediation.

        Args:
            finding: The raw scanner finding to enrich.
            file_path: Absolute path to the file containing the vulnerability.
            raise_on_error: If True, propagates exceptions rather than swallowing them.

        Returns:
            The same finding, enriched with reasoning_chain and fixed_code
            if the agent is available. Falls back silently on failure.
        """
        if not self._binary:
            finding.reasoning_chain = (
                "ZeroClaw agent binary not found. "
                "Install it: curl -fsSL https://raw.githubusercontent.com/zeroclaw-labs/zeroclaw/master/install.sh | bash  "
                "Then ensure ~/.cargo/bin is in your PATH."
            )
            if raise_on_error:
                raise RuntimeError("ZeroClaw agent binary not found.")
            return finding

        # 1. Extract code context (bounded to prevent huge prompts and Windows command line limits)
        code_context = self._read_file_context(file_path, finding.line_number)

        # 2. Build the combined message (system prompt + finding details)
        #    The `zeroclaw agent -m` flag accepts a single message string.
        #    We embed the system instructions and the vulnerability data together.
        message = (
            f"{self.system_prompt}\n\n"
            f"--- VULNERABILITY TO ANALYZE ---\n"
            f"Vulnerability ID: {finding.id}\n"
            f"Severity: {finding.severity.value}\n"
            f"Category: {finding.category.value}\n"
            f"Title: {finding.title}\n"
            f"Description: {finding.description}\n"
            f"File: {file_path}\n"
            f"Line: {finding.line_number or 'N/A'}\n"
            f"\n--- Source Code ---\n{code_context}"
        )

        # 3. Call the ZeroClaw Rust Agent via CLI
        #    Correct syntax: zeroclaw agent --agent <alias> -m "<message>"
        try:
            result = subprocess.run(
                [
                    self._binary,
                    "agent",
                    "--agent", self.agent_alias,
                    "-m", message,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=True,
                timeout=_AGENT_TIMEOUT_SECONDS,
            )

            # 4. Try to parse JSON from the agent's stdout
            raw_output = result.stdout.strip()
            response_data = self._extract_json(raw_output)

            if response_data:
                # 5. Enrich the finding
                finding.reasoning_chain = response_data.get(
                    "reasoning_chain", "Agent returned no reasoning."
                )
                finding.fixed_code = response_data.get("fixed_code", "")
                logger.info("Enriched finding %s via ZeroClaw agent", finding.id)
            else:
                # Agent responded but not in parseable JSON —
                # use the raw text as the reasoning chain
                finding.reasoning_chain = raw_output or "Agent returned empty response."
                logger.warning(
                    "ZeroClaw agent returned non-JSON for %s — using raw output",
                    finding.id,
                )

        except FileNotFoundError as e:
            # ZeroClaw binary disappeared between init and call
            finding.reasoning_chain = (
                "ZeroClaw agent binary not found at runtime. "
                "Ensure the binary is installed and accessible."
            )
            logger.warning("ZeroClaw binary not found — skipping enrichment for %s", finding.id)
            if raise_on_error:
                raise e

        except subprocess.TimeoutExpired as e:
            finding.reasoning_chain = (
                f"ZeroClaw agent timed out after {_AGENT_TIMEOUT_SECONDS}s. "
                "Raw scanner output only."
            )
            logger.warning("ZeroClaw agent timed out for finding %s", finding.id)
            if raise_on_error:
                raise e

        except subprocess.CalledProcessError as e:
            stderr_snippet = (e.stderr or "")[:2000]
            if "rate limit exceeded" in stderr_snippet.lower() or "429" in stderr_snippet:
                finding.reasoning_chain = (
                    "⚠️ OpenRouter API rate limit exceeded. "
                    "The daily free tier quota has been reached. "
                    "Please configure a paid API key or wait for the limit to reset."
                )
            else:
                finding.reasoning_chain = (
                    f"ZeroClaw agent returned non-zero exit code ({e.returncode}). "
                    f"stderr: {stderr_snippet or 'N/A'}"
                )
            logger.warning("ZeroClaw agent error for %s: %s", finding.id, e)
            if raise_on_error:
                raise e

        except Exception as e:
            # Catch-all: never crash the pipeline
            finding.reasoning_chain = (
                f"ZeroClaw agent unavailable. Raw scanner output only. Error: {e}"
            )
            logger.warning("Unexpected error enriching %s: %s", finding.id, e)
            if raise_on_error:
                raise e

        return finding

    @staticmethod
    def _extract_json(text: str) -> dict | None:
        """Try to extract a JSON object from agent output.

        The agent may wrap JSON in markdown fences or include
        conversational text around it. This method tries:
          1. Direct JSON parse
          2. Extract from ```json ... ``` fences
          3. Find first { ... } block
        """
        # 1. Direct parse
        try:
            return json.loads(text)
        except (json.JSONDecodeError, ValueError):
            pass

        # 2. Markdown JSON fence
        import re
        fence_match = re.search(r"```(?:json)?\s*\n(.*?)\n```", text, re.DOTALL)
        if fence_match:
            try:
                return json.loads(fence_match.group(1))
            except (json.JSONDecodeError, ValueError):
                pass

        # 3. First { ... } block (greedy from first { to last })
        brace_start = text.find("{")
        brace_end = text.rfind("}")
        if brace_start != -1 and brace_end > brace_start:
            try:
                return json.loads(text[brace_start:brace_end + 1])
            except (json.JSONDecodeError, ValueError):
                pass

        return None

    @staticmethod
    def _read_file_context(file_path: Path, line_number: int | None = None) -> str:
        """Read file content bounded to _MAX_CONTEXT_BYTES, centered around line_number if available."""
        try:
            if not file_path.is_file():
                return "Could not load file context: file not found."

            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            if not lines:
                return ""

            if line_number is not None:
                # 1-based index to 0-based index
                target_idx = line_number - 1
                start_idx = max(0, target_idx - 30)
                end_idx = min(len(lines), target_idx + 31)
                
                context_lines = lines[start_idx:end_idx]
                # Mark target line for clarity in prompt
                indicator_idx = target_idx - start_idx
                if 0 <= indicator_idx < len(context_lines):
                    context_lines[indicator_idx] += "  <-- VULNERABLE LINE"
                
                content = "\n".join(context_lines)
            else:
                # Fallback: read first 80 lines
                content = "\n".join(lines[:80])

            if len(content) > _MAX_CONTEXT_BYTES:
                return content[:_MAX_CONTEXT_BYTES] + "\n... [truncated]"
            return content
        except Exception as e:
            return f"Could not load file context: {e}"
