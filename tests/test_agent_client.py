"""Tests for the ZeroClaw Agent Client — mock-based, no Rust binary needed."""
import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from zeroclaw.agent_client import ZeroClawClient, _find_zeroclaw_binary
from zeroclaw.models import Category, Finding, Severity


@pytest.fixture
def sample_finding():
    """A typical raw scanner finding for enrichment testing."""
    return Finding(
        id="PATTERN-0001",
        severity=Severity.HIGH,
        category=Category.CODE_PATTERN,
        title="Possible SQL injection (f-string in execute)",
        description='Possible SQL injection at line 3: cursor.execute(f"SELECT...")',
        file_path="database.py",
        remediation="Use parameterized queries or safe DOM APIs.",
        line_number=3,
    )


@pytest.fixture
def sample_file(tmp_path):
    """A dummy vulnerable file for context loading."""
    f = tmp_path / "database.py"
    f.write_text(
        'def get_user(cursor, user_id):\n'
        '    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
        '    return cursor.fetchone()\n',
        encoding="utf-8",
    )
    return f


def _make_client_with_binary(binary_path="/usr/local/bin/zeroclaw"):
    """Create a ZeroClawClient with a pre-set binary path (skip discovery)."""
    with patch("zeroclaw.agent_client._find_zeroclaw_binary", return_value=binary_path):
        client = ZeroClawClient()
    return client


class TestZeroClawClient:
    """Tests for the ZeroClawClient bridge."""

    def test_prompt_template_loads(self):
        """The client should load the remediation.txt prompt without error."""
        client = _make_client_with_binary()
        assert "ZeroClaw" in client.system_prompt
        assert "reasoning_chain" in client.system_prompt

    def test_is_available_true(self):
        """is_available should be True when binary is found."""
        client = _make_client_with_binary("/usr/local/bin/zeroclaw")
        assert client.is_available is True

    def test_is_available_false(self):
        """is_available should be False when binary is not found."""
        with patch("zeroclaw.agent_client._find_zeroclaw_binary", return_value=None):
            client = ZeroClawClient()
        assert client.is_available is False

    @patch("zeroclaw.agent_client.subprocess.run")
    def test_successful_enrichment(self, mock_run, sample_finding, sample_file):
        """On success, reasoning_chain and fixed_code should be populated."""
        mock_run.return_value = MagicMock(
            stdout=json.dumps({
                "reasoning_chain": "The f-string interpolation allows SQL injection.",
                "fixed_code": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
            }),
            returncode=0,
        )

        client = _make_client_with_binary()
        enriched = client.enrich_finding(sample_finding, sample_file)

        assert enriched.reasoning_chain == "The f-string interpolation allows SQL injection."
        assert enriched.fixed_code == 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
        mock_run.assert_called_once()

    @patch("zeroclaw.agent_client.subprocess.run")
    def test_successful_enrichment_markdown_fenced(self, mock_run, sample_finding, sample_file):
        """Agent may wrap JSON in markdown fences — should still parse."""
        response_json = {
            "reasoning_chain": "SQL injection via f-string.",
            "fixed_code": 'cursor.execute("SELECT ...", (user_id,))',
        }
        mock_run.return_value = MagicMock(
            stdout=f"Here is the analysis:\n```json\n{json.dumps(response_json)}\n```\n",
            returncode=0,
        )

        client = _make_client_with_binary()
        enriched = client.enrich_finding(sample_finding, sample_file)

        assert enriched.reasoning_chain == "SQL injection via f-string."
        assert enriched.fixed_code is not None

    def test_binary_not_found_fallback(self, sample_finding, sample_file):
        """If zeroclaw binary is not found at init, should fall back gracefully."""
        with patch("zeroclaw.agent_client._find_zeroclaw_binary", return_value=None):
            client = ZeroClawClient()
        enriched = client.enrich_finding(sample_finding, sample_file)

        assert enriched.reasoning_chain is not None
        assert "not found" in enriched.reasoning_chain
        # fixed_code should remain None (not set by fallback)
        assert enriched.fixed_code is None

    @patch("zeroclaw.agent_client.subprocess.run")
    def test_agent_timeout_fallback(self, mock_run, sample_finding, sample_file):
        """If agent times out, should fall back gracefully."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="zeroclaw", timeout=60)

        client = _make_client_with_binary()
        enriched = client.enrich_finding(sample_finding, sample_file)

        assert enriched.reasoning_chain is not None
        assert "timed out" in enriched.reasoning_chain

    @patch("zeroclaw.agent_client.subprocess.run")
    def test_agent_error_fallback(self, mock_run, sample_finding, sample_file):
        """If agent returns non-zero exit, should fall back gracefully."""
        mock_run.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd="zeroclaw", stderr="internal error"
        )

        client = _make_client_with_binary()
        enriched = client.enrich_finding(sample_finding, sample_file)

        assert enriched.reasoning_chain is not None
        assert "non-zero exit" in enriched.reasoning_chain

    @patch("zeroclaw.agent_client.subprocess.run")
    def test_non_json_uses_raw_output(self, mock_run, sample_finding, sample_file):
        """If agent returns non-JSON output, use raw text as reasoning."""
        mock_run.return_value = MagicMock(
            stdout="This is a plain text security analysis without JSON.",
            returncode=0,
        )

        client = _make_client_with_binary()
        enriched = client.enrich_finding(sample_finding, sample_file)

        assert enriched.reasoning_chain is not None
        assert "plain text security analysis" in enriched.reasoning_chain

    def test_file_context_reading(self, tmp_path):
        """Should read file content for prompt context."""
        f = tmp_path / "test.py"
        f.write_text("print('hello')", encoding="utf-8")

        context = ZeroClawClient._read_file_context(f)
        assert "print('hello')" in context

    def test_file_context_missing_file(self, tmp_path):
        """Should return fallback when file doesn't exist."""
        missing = tmp_path / "nonexistent.py"
        context = ZeroClawClient._read_file_context(missing)
        assert "Could not load" in context

    def test_enrichment_preserves_original_fields(self, sample_finding, sample_file):
        """Enrichment should NOT modify the original scanner fields."""
        original_id = sample_finding.id
        original_title = sample_finding.title
        original_severity = sample_finding.severity

        # Use binary-not-found path (no subprocess mock needed)
        with patch("zeroclaw.agent_client._find_zeroclaw_binary", return_value=None):
            client = ZeroClawClient()
            enriched = client.enrich_finding(sample_finding, sample_file)

        assert enriched.id == original_id
        assert enriched.title == original_title
        assert enriched.severity == original_severity

    @patch("zeroclaw.agent_client.subprocess.run")
    def test_correct_cli_args(self, mock_run, sample_finding, sample_file):
        """Subprocess should be called with 'agent --agent scanner -m ...' syntax."""
        mock_run.return_value = MagicMock(
            stdout=json.dumps({"reasoning_chain": "test", "fixed_code": ""}),
            returncode=0,
        )

        client = _make_client_with_binary("/usr/local/bin/zeroclaw")
        client.enrich_finding(sample_finding, sample_file)

        call_args = mock_run.call_args[0][0]
        assert call_args[0] == "/usr/local/bin/zeroclaw"
        assert call_args[1] == "agent"
        assert call_args[2] == "--agent"
        assert call_args[3] == "scanner"  # default alias
        assert call_args[4] == "-m"

    def test_custom_agent_alias(self):
        """Client should accept a custom agent alias."""
        client = _make_client_with_binary()
        # Default alias
        assert client.agent_alias == "scanner"

        # Custom alias via constructor
        with patch("zeroclaw.agent_client._find_zeroclaw_binary", return_value="/bin/zeroclaw"):
            client = ZeroClawClient(agent_alias="custom-agent")
        assert client.agent_alias == "custom-agent"

    def test_raise_on_error_binary_not_found(self, sample_finding, sample_file):
        """Should raise RuntimeError if binary is not found and raise_on_error=True."""
        with patch("zeroclaw.agent_client._find_zeroclaw_binary", return_value=None):
            client = ZeroClawClient()
        import pytest
        with pytest.raises(RuntimeError, match="ZeroClaw agent binary not found"):
            client.enrich_finding(sample_finding, sample_file, raise_on_error=True)

    @patch("zeroclaw.agent_client.subprocess.run")
    def test_raise_on_error_timeout(self, mock_run, sample_finding, sample_file):
        """Should propagate TimeoutExpired if raise_on_error=True."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="zeroclaw", timeout=60)
        client = _make_client_with_binary()
        import pytest
        with pytest.raises(subprocess.TimeoutExpired):
            client.enrich_finding(sample_finding, sample_file, raise_on_error=True)

    @patch("zeroclaw.agent_client.subprocess.run")
    def test_raise_on_error_subprocess_error(self, mock_run, sample_finding, sample_file):
        """Should propagate CalledProcessError if raise_on_error=True."""
        mock_run.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd="zeroclaw", stderr="rate limit exceeded"
        )
        client = _make_client_with_binary()
        import pytest
        with pytest.raises(subprocess.CalledProcessError):
            client.enrich_finding(sample_finding, sample_file, raise_on_error=True)


class TestExtractJson:
    """Tests for the _extract_json helper."""

    def test_direct_json(self):
        """Should parse raw JSON directly."""
        result = ZeroClawClient._extract_json('{"reasoning_chain": "test", "fixed_code": "x"}')
        assert result == {"reasoning_chain": "test", "fixed_code": "x"}

    def test_markdown_fenced_json(self):
        """Should extract JSON from markdown code fences."""
        text = 'Some analysis:\n```json\n{"reasoning_chain": "a", "fixed_code": "b"}\n```\nDone.'
        result = ZeroClawClient._extract_json(text)
        assert result is not None
        assert result["reasoning_chain"] == "a"

    def test_embedded_braces(self):
        """Should find JSON embedded in surrounding text."""
        text = 'Here is my analysis: {"reasoning_chain": "vuln", "fixed_code": "fix"} end.'
        result = ZeroClawClient._extract_json(text)
        assert result is not None
        assert result["reasoning_chain"] == "vuln"

    def test_no_json(self):
        """Should return None when no JSON is found."""
        result = ZeroClawClient._extract_json("This is just plain text with no JSON.")
        assert result is None


class TestFindingModelBackwardCompat:
    """Ensure the new Optional fields don't break existing Finding construction."""

    def test_finding_without_enrichment_fields(self):
        """Creating a Finding without enrichment fields should work (backward compat)."""
        f = Finding(
            id="TEST-001",
            severity=Severity.HIGH,
            category=Category.SECRET,
            title="Test finding",
            description="Test",
            file_path="test.py",
            remediation="Fix it",
        )
        assert f.reasoning_chain is None
        assert f.fixed_code is None

    def test_finding_with_enrichment_fields(self):
        """Creating a Finding WITH enrichment fields should also work."""
        f = Finding(
            id="TEST-002",
            severity=Severity.CRITICAL,
            category=Category.INJECTION,
            title="SQL Injection",
            description="Bad query",
            file_path="db.py",
            remediation="Use parameterized queries",
            reasoning_chain="The query uses string concatenation...",
            fixed_code='cursor.execute("SELECT ...", (param,))',
        )
        assert f.reasoning_chain == "The query uses string concatenation..."
        assert f.fixed_code == 'cursor.execute("SELECT ...", (param,))'
