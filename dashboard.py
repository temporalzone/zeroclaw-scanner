"""ZeroClaw Security Dashboard — Phase 4
Dynamic Scan Control Panel + Live ZeroClaw AI Remediation Guide
"""
import os
import stat
import uuid
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime
import streamlit as st
import pandas as pd

# Sync Streamlit secrets to environment variables to ensure subprocesses can access them.
try:
    for key in st.secrets:
        val = st.secrets[key]
        if isinstance(val, str) and val:
            os.environ[key] = val
except Exception:
    pass

# Auto-compile/install ZeroClaw agent binary on Streamlit Cloud if missing
try:
    import shutil
    import subprocess
    import os
    import urllib.request
    import tarfile
    import zipfile
    import platform
    from pathlib import Path
    
    cargo_name = "zeroclaw.exe" if os.name == "nt" else "zeroclaw"
    cargo_path = Path.home() / ".cargo" / "bin" / cargo_name
    print(f"[ZeroClaw Build] cargo_path={cargo_path}, exists={cargo_path.exists()}, cargo_in_path={shutil.which('cargo')}")
    
    # 1. Ensure config directory and config.toml exist with API key configured
    config_dir = Path.home() / ".zeroclaw"
    config_path = config_dir / "config.toml"
    
    api_key = ""
    try:
        if "OPENROUTER_API_KEY" in st.secrets:
            api_key = st.secrets["OPENROUTER_API_KEY"]
    except Exception:
        pass
    if not api_key:
        api_key = os.environ.get("OPENROUTER_API_KEY", "")
        
    # Overwrite/write config.toml if it's missing, or if we have an API key to update
    if api_key or not config_path.exists():
        print(f"[ZeroClaw Build] Writing/updating ~/.zeroclaw/config.toml (api_key length={len(api_key)})")
        config_dir.mkdir(parents=True, exist_ok=True)
        default_config = f"""schema_version = 3

[providers.models.openrouter.scanner]
model = "google/gemma-2-9b-it:free"
temperature = 0.2
api_key = "{api_key}"
max_tokens = 4096
fallback_models = []
native_tools = false

[agents.scanner]
model_provider = "openrouter.scanner"
risk_profile = "default"
skill_bundles = []
enabled = true

[risk_profiles.default]
level = "full"
workspace_only = false
block_high_risk_commands = false
"""
        config_path.write_text(default_config, encoding="utf-8")
        print("[ZeroClaw Build] Configuration file configured successfully.")

    # 2. Download or compile binary
    if not cargo_path.exists():
        print("[ZeroClaw Build] Rust binary missing. Attempting to download pre-built binary...")
        try:
            system = platform.system().lower()
            machine = platform.machine().lower()
            url = None
            is_zip = False
            version = "v0.8.0"
            
            if system == "linux" and ("x86_64" in machine or "amd64" in machine):
                url = f"https://github.com/zeroclaw-labs/zeroclaw/releases/download/{version}/zeroclaw-x86_64-unknown-linux-gnu.tar.gz"
                is_zip = False
            elif system == "windows" and ("64" in machine or "amd64" in machine):
                url = f"https://github.com/zeroclaw-labs/zeroclaw/releases/download/{version}/zeroclaw-x86_64-pc-windows-msvc.zip"
                is_zip = True
                
            if url:
                print(f"[ZeroClaw Build] Downloading pre-built ZeroClaw from {url}...")
                cargo_path.parent.mkdir(parents=True, exist_ok=True)
                temp_file, _ = urllib.request.urlretrieve(url)
                print(f"[ZeroClaw Build] Downloaded to temp file: {temp_file}")
                
                if is_zip:
                    with zipfile.ZipFile(temp_file, 'r') as zip_ref:
                        for member in zip_ref.namelist():
                            if member.endswith("zeroclaw.exe"):
                                with zip_ref.open(member) as source, open(cargo_path, 'wb') as target:
                                    target.write(source.read())
                else:
                    with tarfile.open(temp_file, 'r:gz') as tar_ref:
                        for member in tar_ref.getmembers():
                            if member.name == "zeroclaw" or member.name.endswith("/zeroclaw"):
                                source = tar_ref.extractfile(member)
                                if source:
                                    with open(cargo_path, 'wb') as target:
                                        target.write(source.read())
                                        
                if os.name != "nt":
                    os.chmod(cargo_path, 0o755)
                print(f"[ZeroClaw Build] Successfully installed pre-built binary to {cargo_path}")
            else:
                raise ValueError(f"No pre-built binary download URL mapped for system={system}, machine={machine}")
        except Exception as download_err:
            print(f"[ZeroClaw Build] Pre-built binary download failed: {download_err}. Falling back to cargo compile...")
            env = os.environ.copy()
            if not shutil.which("cargo") and os.path.exists("/usr/bin/cargo"):
                env["PATH"] = f"/usr/bin{os.path.pathsep}{env.get('PATH', '')}"
            subprocess.run(["cargo", "install", "zeroclaw"], check=True, capture_output=True, env=env)
            print("[ZeroClaw Build] ZeroClaw Rust agent binary compiled successfully.")
except Exception as e:
    print(f"[ZeroClaw Build] ZeroClaw agent install warning: {e}")


# Import verification logic from verify_fix
from verify_fix import verify_finding, TRACKER_FILE, load_tracker, save_tracker

st.set_page_config(
    page_title="ZeroClaw — Security Dashboard",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Splash Screen Preloader ───────────────────────────────────────────────────
if "splash_shown" not in st.session_state:
    st.session_state.splash_shown = False

if not st.session_state.splash_shown:
    st.markdown("""
    <style>
    [data-testid="stSidebar"] { display: none !important; }
    header[data-testid="stHeader"] { display: none !important; }
    .stApp { background: #0b0f19 !important; }
    
    .splash-container {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        height: 80vh;
        text-align: center;
        font-family: 'Inter', sans-serif;
    }
    .splash-logo {
        font-size: 72px;
        margin-bottom: 20px;
        animation: pulseLogo 2s infinite ease-in-out;
    }
    .splash-title {
        font-size: 48px;
        font-weight: 800;
        color: #F8FAFC;
        letter-spacing: -1px;
        background: linear-gradient(90deg, #F8FAFC, #38bdf8);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        animation: fadeInTitle 1.2s ease-out forwards;
    }
    .splash-subtitle {
        font-size: 13px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.15em;
        color: #38bdf8;
        margin-top: 10px;
        opacity: 0;
        animation: fadeInText 1s 0.4s ease-out forwards;
    }
    .splash-loader-bar {
        width: 280px;
        height: 4px;
        background: #1e293b;
        border-radius: 2px;
        margin-top: 32px;
        overflow: hidden;
        position: relative;
    }
    .splash-loader-fill {
        height: 100%;
        width: 0;
        background: #38bdf8;
        border-radius: 2px;
        animation: loadProgress 2.5s ease-out forwards;
    }
    .splash-status {
        font-size: 12px;
        color: #64748b;
        margin-top: 12px;
        font-family: 'JetBrains Mono', monospace;
        opacity: 0;
        animation: fadeInText 1s 0.8s ease-out forwards;
    }

    @keyframes pulseLogo {
        0% { transform: scale(0.95); filter: drop-shadow(0 0 10px rgba(56, 189, 248, 0.1)); }
        50% { transform: scale(1.05); filter: drop-shadow(0 0 25px rgba(56, 189, 248, 0.4)); }
        100% { transform: scale(0.95); filter: drop-shadow(0 0 10px rgba(56, 189, 248, 0.1)); }
    }
    @keyframes fadeInTitle {
        0% { opacity: 0; transform: translateY(-10px); }
        100% { opacity: 1; transform: translateY(0); }
    }
    @keyframes fadeInText {
        0% { opacity: 0; }
        100% { opacity: 1; }
    }
    @keyframes loadProgress {
        0% { width: 0%; }
        20% { width: 15%; }
        50% { width: 45%; }
        80% { width: 85%; }
        100% { width: 100%; }
    }
    </style>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    <div class="splash-container">
        <div class="splash-logo">🔐</div>
        <div class="splash-title">ZeroClaw</div>
        <div class="splash-subtitle">Continuous Threat Detection & Autonomous AI Remediation</div>
        <div class="splash-loader-bar">
            <div class="splash-loader-fill"></div>
        </div>
        <div class="splash-status">Initializing security modules...</div>
    </div>
    """, unsafe_allow_html=True)
    
    import time
    time.sleep(2.6)
    st.session_state.splash_shown = True
    st.rerun()

# Add src/ to python path for backend scanner imports
import sys
sys.path.insert(0, str(Path(__file__).parent / "src"))

# ── CSS Styling ───────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');
html,body,[class*="css"]{font-family:'Inter',sans-serif;}
.stApp{background:#0b0f19;color:#F1F5F9;}
[data-testid="stSidebar"]{background:#0e1322!important;border-right:1px solid #1e293b;}
header[data-testid="stHeader"]{display:none;}

/* Highlighting widgets & bright labels */
div[data-testid="stWidgetLabel"] p {
    color: #e2e8f0 !important;
    font-size: 13.5px !important;
    font-weight: 600 !important;
}

/* Force dark theme for selectboxes and multiselects */
div[data-baseweb="select"] > div {
    background-color: #161d30 !important;
    color: #F1F5F9 !important;
    border: 1px solid #24304a !important;
}

/* Force dark theme for text input fields */
input[type="text"], div[data-testid="stTextInput"] input {
    background-color: #161d30 !important;
    color: #F1F5F9 !important;
    border: 1px solid #24304a !important;
}

/* Style selected tag options inside multiselect to be dark and readable */
span[data-baseweb="tag"] {
    background-color: #1e293b !important;
    color: #F1F5F9 !important;
    border: 1px solid #38bdf8 !important;
    border-radius: 4px !important;
}

/* Style selectbox dropdown option lists */
div[role="listbox"] {
    background-color: #161d30 !important;
    color: #F1F5F9 !important;
    border: 1px solid #24304a !important;
}
div[role="option"] {
    background-color: #161d30 !important;
    color: #F1F5F9 !important;
}
div[role="option"]:hover {
    background-color: #1e293b !important;
}

/* Style all standard secondary buttons (e.g. Reload Tracker DB, etc) */
button[data-testid="baseButton-secondary"] {
    background-color: #161d30 !important;
    color: #F1F5F9 !important;
    border: 1px solid #24304a !important;
    font-weight: 600 !important;
    transition: all 0.2s ease-in-out !important;
}
button[data-testid="baseButton-secondary"]:hover {
    background-color: #1e293b !important;
    border-color: #38bdf8 !important;
    color: #38bdf8 !important;
    box-shadow: 0 0 10px rgba(56, 189, 248, 0.2) !important;
}

/* Style primary buttons (e.g. Run Security Scan) */
button[data-testid="baseButton-primary"] {
    background-color: #38bdf8 !important;
    color: #0b0f19 !important;
    border: 1px solid #38bdf8 !important;
    font-weight: 700 !important;
    transition: all 0.2s ease-in-out !important;
}
button[data-testid="baseButton-primary"]:hover {
    background-color: #0ea5e9 !important;
    border-color: #0ea5e9 !important;
    color: #ffffff !important;
    box-shadow: 0 0 12px rgba(56, 189, 248, 0.4) !important;
}

/* Clean Static Metrics */
.metric-card{
    background:#161d30;
    border:1px solid #24304a;
    border-radius:8px;
    padding:18px 20px;
    text-align:center;
}
.metric-number{font-size:36px;font-weight:700;font-family:'JetBrains Mono',monospace;color:#F8FAFC;}
.metric-label{font-size:11px;color:#94A3B8;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;margin-top:4px;}

/* Clean Scorecard Grid Cards */
.scorecard-card {
    background:#161d30;
    border:1px solid #24304a;
    border-radius:8px;
    padding:16px 14px;
    margin-bottom:8px;
}

.section-header{font-size:11px;font-weight:600;letter-spacing:0.12em;text-transform:uppercase;color:#64748B;margin:28px 0 14px 0;padding-bottom:8px;border-bottom:1px solid #1E2A45;}
.badge-critical{background:#450A0A;color:#FCA5A5;border:1px solid #7F1D1D;padding:2px 10px;border-radius:20px;font-size:11px;font-weight:600;font-family:'JetBrains Mono',monospace;}
.badge-high{background:#431407;color:#FDBA74;border:1px solid #7C2D12;padding:2px 10px;border-radius:20px;font-size:11px;font-weight:600;font-family:'JetBrains Mono',monospace;}
.badge-medium{background:#422006;color:#FDE68A;border:1px solid #78350F;padding:2px 10px;border-radius:20px;font-size:11px;font-weight:600;font-family:'JetBrains Mono',monospace;}
.badge-low{background:#0C1A3A;color:#93C5FD;border:1px solid #1E3A6E;padding:2px 10px;border-radius:20px;font-size:11px;font-weight:600;font-family:'JetBrains Mono',monospace;}
.score-bar-bg{background:#0b0f19;border-radius:4px;height:6px;width:100%;margin-top:6px;}
.score-bar-fill{height:6px;border-radius:4px;}

/* Streamlit Tabs Customization */
div[data-testid="stTabBar"] button {
    font-family: 'Inter', sans-serif;
    font-size: 13px !important;
    font-weight: 600 !important;
    color: #94A3B8 !important;
    border-bottom: 2px solid transparent !important;
    padding: 8px 12px !important;
}
div[data-testid="stTabBar"] button[aria-selected="true"] {
    color: #38BDF8 !important;
    border-bottom: 2px solid #38BDF8 !important;
}

/* Animated Intro Banner */
@keyframes slideDownFade {
    0% {
        opacity: 0;
        transform: translateY(-15px);
    }
    100% {
        opacity: 1;
        transform: translateY(0);
    }
}
.intro-banner {
    animation: slideDownFade 0.8s cubic-bezier(0.16, 1, 0.3, 1) forwards;
    background: linear-gradient(135deg, #0e1322 0%, #161d30 100%);
    border: 1px solid #24304a;
    border-left: 4px solid #38bdf8;
    border-radius: 8px;
    padding: 24px;
    margin: 20px 0;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
}
.intro-logo {
    font-size: 28px;
    font-weight: 700;
    color: #F8FAFC;
    font-family: 'Inter', sans-serif;
}
.intro-tagline {
    font-size: 13px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #38bdf8;
    margin-top: 6px;
}
.intro-desc {
    font-size: 13.5px;
    color: #94A3B8;
    line-height: 1.6;
    margin-top: 12px;
}

/* Animated Scanner Container */
.scanner-container {
    background: #0e1322 !important;
    border: 1px solid #24304a !important;
    border-radius: 8px !important;
    padding: 32px 24px !important;
    text-align: center !important;
    position: relative !important;
    overflow: hidden !important;
    margin: 20px 0 !important;
    box-shadow: 0 4px 15px rgba(0,0,0,0.3) !important;
}
.scan-bar {
    height: 3px !important;
    background: linear-gradient(90deg, transparent, #38bdf8, transparent) !important;
    width: 100% !important;
    position: absolute !important;
    top: 0 !important;
    left: -100% !important;
    animation: scanInfinite 2.5s infinite linear !important;
}
.radar-ping {
    width: 48px !important;
    height: 48px !important;
    border: 2px solid #38bdf8 !important;
    border-radius: 50% !important;
    margin: 0 auto !important;
    animation: radarPulse 1.8s infinite ease-out !important;
    opacity: 0;
}
@keyframes scanInfinite {
    0% { left: -100%; }
    100% { left: 100%; }
}
@keyframes radarPulse {
    0% { transform: scale(0.6); opacity: 1; }
    100% { transform: scale(1.4); opacity: 0; }
}
</style>
""", unsafe_allow_html=True)

# ── Stream metadata ───────────────────────────────────────────────────────────
STREAM_META = {
    "Boardy":       {"name": "Boardy",       "color": "#6366F1", "repo": "boardy-agents"},
    "DataPro+":     {"name": "DataPro+",     "color": "#EC4899", "repo": "datapro-platform"},
    "VSAB+3D":      {"name": "VSAB+3D",      "color": "#10B981", "repo": "vsab-twin"},
    "Altiostar":    {"name": "Altiostar",    "color": "#F59E0B", "repo": "altiostar-mro"},
    "Security":     {"name": "Security",     "color": "#2DD4BF", "repo": "zeroclaw-scanner"},
    "LPI Platform": {"name": "LPI Platform", "color": "#3B82F6", "repo": "lpi-platform"},
}

def load_all_findings():
    """Load findings from tracker and format for dashboard use."""
    findings = load_tracker()
    formatted = []
    scan_files = []
    
    for f in findings:
        stream = f.get("stream", "Security")
        meta = STREAM_META.get(stream, {"name": stream, "color": "#64748B", "repo": "unknown"})
        
        # Determine category details
        cat = f.get("category", "pattern")
        
        # Stride Mapping
        stride = f.get("stride", "—")
        if stride == "—":
            if cat == "auth":
                stride = "Elevation of Privilege"
            elif cat == "secret":
                stride = "Information Disclosure"
            else:
                stride = "Tampering"
                
        # Build formatted item
        item = {
            "id": f.get("id", "—"),
            "stream": stream,
            "repo": meta["repo"] if stream in STREAM_META else "custom-repo",
            "tool": f.get("scanner", "All Scanners"),
            "timestamp": f.get("timestamp", "2026-06-17T20:53:55Z"),
            "severity": f.get("severity", "LOW").upper(),
            "stride": stride,
            "owasp": f.get("owasp", "LA-01"),
            "component": f.get("file", "—"),
            "line": f.get("line"),
            "version": "",
            "description": f.get("title", f.get("description", "—")),
            "fixed_version": "",
            "steps": f.get("remediation", "—"),
            "status": f.get("status", "Open"),
            "category": cat,
            "reasoning_chain": f.get("reasoning_chain"),
            "fixed_code": f.get("fixed_code"),
            "remediation_enabled": f.get("remediation_enabled", True)  # Tracks if enrichment was selected
        }
        formatted.append(item)
        
    # Build unique scan file summaries
    for f in formatted:
        stream = f["stream"]
        tool = f["tool"]
        if not any(sf["stream"] == stream and sf["tool"] == tool for sf in scan_files):
            scan_files.append({
                "file": f"{stream.lower().replace(' ', '_')}_scan.json",
                "stream": stream,
                "repo": f["repo"],
                "tool": tool,
                "env": "local-dev-env",
                "timestamp": f["timestamp"],
                "commit": "0000000",
                "total": len([x for x in formatted if x["stream"] == stream]),
                "critical": len([x for x in formatted if x["stream"] == stream and x["severity"] == "CRITICAL"]),
                "high": len([x for x in formatted if x["stream"] == stream and x["severity"] == "HIGH"]),
                "medium": len([x for x in formatted if x["stream"] == stream and x["severity"] == "MEDIUM"]),
                "low": len([x for x in formatted if x["stream"] == stream and x["severity"] == "LOW"]),
            })
            
    return formatted, scan_files

# ── Load and Render Remediation Files ─────────────────────────────────────────
def get_remediation_guide(category, title_desc):
    """Map category and description to the correct markdown remediation guide."""
    cat = category.lower()
    td = title_desc.lower()
    
    file_name = None
    if "auth" in cat:
        if "rls" in td or "supabase" in td:
            file_name = "missing-rls.md"
        else:
            file_name = "unprotected-routes.md"
    elif "secret" in cat:
        file_name = "hardcoded-secrets.md"
    elif "dependency" in cat:
        file_name = "unpinned-deps.md"
    else:  # pattern, injection
        if "sql" in td:
            file_name = "sqli.md"
        elif "command" in td or "shell" in td or "subprocess" in td:
            file_name = "command-injection.md"
        else:
            file_name = "xss.md"
            
    if file_name:
        guide_path = Path(__file__).parent / "remediation" / file_name
        if guide_path.exists():
            try:
                return guide_path.read_text(encoding="utf-8")
            except Exception:
                pass
    return None

# ── Git Cloning Backend Helper ────────────────────────────────────────────────
def handle_git_clone(repo_url):
    """Clones a remote Git URL to a temporary workspace folder."""
    # Create a unique temporary directory name for this clone operation
    unique_id = str(uuid.uuid4())[:8]
    clone_dir = Path(tempfile.gettempdir()) / f"zeroclaw_clone_{unique_id}"
    
    if clone_dir.exists():
        try:
            # Change permissions of all files to make them writable
            for root, dirs, files in os.walk(clone_dir):
                for d in dirs:
                    os.chmod(os.path.join(root, d), stat.S_IWRITE)
                for f in files:
                    os.chmod(os.path.join(root, f), stat.S_IWRITE)
            shutil.rmtree(clone_dir, ignore_errors=True)
        except Exception:
            pass
            
    try:
        subprocess.run(["git", "clone", "--depth", "1", repo_url, str(clone_dir)], check=True, capture_output=True, text=True)
        return clone_dir
    except subprocess.CalledProcessError as e:
        raise ValueError(f"Git clone failed: {e.stderr or e}")

# ── Auto-Infer Stream Name from Path ─────────────────────────────────────────
def infer_stream_name(target_path_str: str) -> str:
    """Automatically maps repository path to stream name to prevent user errors."""
    resolved_path_str = target_path_str
    if not target_path_str.startswith(("http://", "https://", "git@")):
        try:
            resolved_path_str = str(Path(target_path_str).resolve())
        except Exception:
            pass
            
    path_lower = resolved_path_str.lower()
    if "lpi" in path_lower:
        return "LPI Platform"
    elif "boardy" in path_lower or "voice" in path_lower:
        return "Boardy"
    elif "datapro" in path_lower:
        return "DataPro+"
    elif "vsab" in path_lower or "twin" in path_lower:
        return "VSAB+3D"
    elif "altiostar" in path_lower or "mro" in path_lower:
        return "Altiostar"
    elif "security" in path_lower or "zeroclaw" in path_lower or "auth-proxy" in path_lower:
        return "Security"
    else:
        # Extract base folder name from local path or git URL
        try:
            # Check if Git URL
            if target_path_str.startswith(("http://", "https://", "git@")):
                name = target_path_str.split("/")[-1].replace(".git", "")
                return name
            p = Path(target_path_str).resolve()
            name = p.name
            if name in (".", "", "/"):
                name = p.parent.name
            return name or "Custom Stream"
        except Exception:
            return "Custom Stream"

# ── Live Scan Backend Execution ───────────────────────────────────────────────
def run_scan_backend(target_path_str: str, stream_name: str, enable_enrich: bool):
    """Runs static scanners and optional AI agent enrichment on target path."""
    from zeroclaw.scanners.pattern_scanner import scan_patterns
    from zeroclaw.scanners.dependency_scanner import scan_dependencies
    from zeroclaw.scanners.secret_scanner import scan_secrets
    from zeroclaw.scanners.auth_scanner import scan_fastapi_auth, scan_supabase_rls
    from zeroclaw.agent_client import ZeroClawClient
    
    # Check for Git URL
    if target_path_str.startswith(("http://", "https://", "git@")):
        st.info(f"Cloning remote repository: {target_path_str} ...")
        target = handle_git_clone(target_path_str)
    else:
        target = Path(target_path_str).resolve()
        if not target.exists():
            raise ValueError(f"Target folder '{target_path_str}' does not exist.")
            
    findings = []
    
    # 1. Run static scanners
    st.text("Running Pattern Scanner...")
    try:
        patterns = scan_patterns(target)
        findings.extend(patterns)
    except Exception as e:
        st.warning(f"Pattern scanner warning: {e}")
        
    st.text("Running Dependency Scanner...")
    try:
        deps = scan_dependencies(target)
        findings.extend(deps)
    except Exception as e:
        st.warning(f"Dependency scanner warning: {e}")
        
    st.text("Running Secret Scanner...")
    try:
        secrets = scan_secrets(target, allowed_base=target)
        findings.extend(secrets)
    except Exception as e:
        st.warning(f"Secret scanner warning: {e}")
        
    st.text("Running Auth Scanners...")
    try:
        auth = scan_fastapi_auth(target)
        findings.extend(auth)
    except Exception as e:
        st.warning(f"FastAPI Auth scanner warning: {e}")
        
    try:
        rls = scan_supabase_rls(target)
        findings.extend(rls)
    except NotImplementedError:
        pass
    except Exception as e:
        st.warning(f"Supabase RLS scanner warning: {e}")
        
    # Set stream property
    for f in findings:
        f.stream = stream_name
        
    # 2. Run ZeroClaw AI Agent Enrichment if selected
    if enable_enrich:
        enrichable = [
            f for f in findings 
            if f.severity.value in ("critical", "high", "medium")
        ]
        
        if enrichable:
            # Try to load existing tracker data to reuse already-enriched findings
            existing_findings = []
            try:
                existing_findings = load_tracker()
            except Exception:
                pass
            
            # Map existing findings by (filename_lower, line_number, title_lower)
            existing_map = {}
            for ef in existing_findings:
                file_key = ef.get("file", "")
                if file_key:
                    try:
                        file_key = Path(file_key).name.lower()
                    except Exception:
                        file_key = str(file_key).lower()
                
                key = (file_key, ef.get("line"), ef.get("title", "").strip().lower())
                existing_map[key] = ef
            
            progress_status = st.empty()
            progress_bar = st.progress(0)
            
            client = ZeroClawClient()
            import time
            consecutive_failures = 0
            for i, finding in enumerate(enrichable, 1):
                # Extract filename for key matching
                file_key = ""
                if finding.file_path:
                    try:
                        file_key = Path(finding.file_path).name.lower()
                    except Exception:
                        file_key = str(finding.file_path).lower()
                
                key = (file_key, finding.line_number, finding.title.strip().lower())
                matched = existing_map.get(key)
                
                # If we have a successful previous run for this finding, reuse it to avoid API delays
                if matched and matched.get("reasoning_chain") and not any(
                    ind in matched.get("reasoning_chain", "").lower()
                    for ind in ["skipped due to", "timed out", "failed", "unavailable", "not found"]
                ):
                    finding.reasoning_chain = matched["reasoning_chain"]
                    finding.fixed_code = matched.get("fixed_code")
                    progress_status.markdown(
                        f"⚡ **Reused AI reasoning** for `{finding.id or f'ZC-{i:03d}'}` (*{finding.title}*)"
                    )
                    progress_bar.progress(i / len(enrichable))
                    continue
                
                if consecutive_failures >= 5:
                    finding.reasoning_chain = (
                        "ZeroClaw agent skipped due to consecutive API/timeout errors."
                    )
                    progress_bar.progress(i / len(enrichable))
                    continue
                
                progress_status.markdown(
                    f"🧬 **Enriching finding {i} of {len(enrichable)}** (`{finding.id or f'ZC-{i:03d}'}` - *{finding.title}*)..."
                )
                progress_bar.progress(i / len(enrichable))
                
                # Sleep briefly to avoid tight rate-limiting, and longer if we recently failed
                if i > 1:
                    sleep_time = 5.0 if consecutive_failures > 0 else 1.5
                    time.sleep(sleep_time)
                
                file_to_enrich = target / finding.file_path
                try:
                    client.enrich_finding(finding, file_to_enrich, raise_on_error=True)
                    consecutive_failures = 0
                except Exception as e:
                    consecutive_failures += 1
                    # client.enrich_finding already populated finding.reasoning_chain with the error details
            
            # Clean up status widgets
            progress_status.empty()
            progress_bar.empty()
                
    return findings, target

# ── Load initial data ─────────────────────────────────────────────────────────
findings, scan_files = load_all_findings()

if "findings" not in st.session_state or len(st.session_state.findings) != len(findings):
    st.session_state.findings = findings

if "active_stream" not in st.session_state:
    st.session_state.active_stream = None

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="padding:8px 0 24px 0;">
        <div style="font-size:22px;font-weight:700;color:#F1F5F9;">🔐 ZeroClaw</div>
        <div style="font-size:11px;color:#64748B;text-transform:uppercase;letter-spacing:0.1em;margin-top:2px;">Security Dashboard · Phase 4</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="section-header">Filters</div>', unsafe_allow_html=True)

    all_streams = sorted(list(set(f["stream"] for f in st.session_state.findings))) if st.session_state.findings else []
    default_selection = [st.session_state.active_stream] if st.session_state.get("active_stream") in all_streams else all_streams
    sel_streams = st.multiselect("Stream", all_streams, default=default_selection)

    sel_severities = st.multiselect("Severity", ["CRITICAL","HIGH","MEDIUM","LOW"], default=["CRITICAL","HIGH","MEDIUM","LOW"])
    sel_statuses   = st.multiselect("Status",   ["Open","Fixed","Verified","Fixed (unverified)"], default=["Open","Fixed","Verified","Fixed (unverified)"])

    st.markdown("---")
    if st.button("🔄 Reload Tracker DB", use_container_width=True):
        st.cache_data.clear()
        st.session_state.findings, _ = load_all_findings()
        st.toast("Database reloaded successfully!", icon="✅")
        st.rerun()

    st.markdown('<div class="section-header">Agent Diagnostics</div>', unsafe_allow_html=True)
    from zeroclaw.agent_client import _find_zeroclaw_binary
    bin_p = _find_zeroclaw_binary()
    if bin_p:
        st.markdown("<span style='color:#34D399;font-size:12px;'>✅ Agent Binary: Found</span>", unsafe_allow_html=True)
    else:
        st.markdown("<span style='color:#F87171;font-size:12px;'>❌ Agent Binary: Not Found</span>", unsafe_allow_html=True)
        
    api_key_ok = False
    try:
        if "OPENROUTER_API_KEY" in st.secrets and st.secrets["OPENROUTER_API_KEY"]:
            api_key_ok = True
    except Exception:
        pass
    if not api_key_ok:
        api_key_ok = bool(os.environ.get("OPENROUTER_API_KEY"))
        
    if api_key_ok:
        st.markdown("<span style='color:#34D399;font-size:12px;'>✅ API Key: Configured</span>", unsafe_allow_html=True)
    else:
        st.markdown("<span style='color:#FBBF24;font-size:12px;'>⚠️ API Key: Missing (Set in Streamlit secrets)</span>", unsafe_allow_html=True)

    st.markdown("""
    <div style="font-size:11px;color:#334155;margin-top:12px;">
        <div style="margin-bottom:6px;font-weight:600;color:#64748B;text-transform:uppercase;letter-spacing:0.08em;">Team</div>
        <div style="margin-bottom:3px;">👑 Varshit · Lead</div>
        <div style="margin-bottom:3px;">🛠 Naman · Remediation</div>
        <div style="margin-bottom:3px;">📊 Sania · QA + Scorecard</div>
        <div>🤖 Kailash · CI Automation</div>
    </div>
    """, unsafe_allow_html=True)

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="intro-banner" style="padding: 16px 20px; border-left: 3px solid #38bdf8;">
    <div class="intro-logo" style="font-size: 22px;">🔐 ZeroClaw Security Dashboard</div>
    <div class="intro-tagline" style="font-size: 11px; margin-top: 3px;">Continuous Threat Detection & Autonomous AI Remediation</div>
</div>
""", unsafe_allow_html=True)

# ── Dynamic Scan Control Panel ────────────────────────────────────────────────
st.markdown("### 📡 Live Scan Control Center")
with st.container():
    c_path, c_agent = st.columns([5, 3])
    with c_path:
        target_input = st.text_input("Repository Path or Git URL", value=".", help="Local directory (e.g. c:\\Users\\mrvar\\lpi-platform) or Git HTTP URL")
    with c_agent:
        enable_enrichment = st.checkbox("Enable ZeroClaw AI Agent Enrichment", value=True, help="Send results to Rust Agent for remediation chain code generation")
        
    run_scan_clicked = st.button("🚀 Run Security Scan", use_container_width=True)
    
    if run_scan_clicked:
        scan_placeholder = st.empty()
        try:
            scan_placeholder.markdown("""
            <div class="scanner-container">
                <div class="scan-bar"></div>
                <div class="radar-ping"></div>
                <div style="font-size: 16px; font-weight: 700; color: #38bdf8; margin-top: 16px;">
                    📡 ZeroClaw Engine Scanning Repository...
                </div>
                <div style="font-size: 13px; color: #94a3b8; margin-top: 6px; line-height: 1.4;">
                    Running dependency scans, credential search, and code pattern analysis.<br>
                    Sending findings to the compiled Rust Agent for AI enrichment.
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            with st.spinner("Executing ZeroClaw security scan pipeline in the backend..."):
                # Automatically detect the correct stream/team label based on target path
                inferred_stream = infer_stream_name(target_input)
                
                scanned_findings, resolved_target = run_scan_backend(target_input, inferred_stream, enable_enrichment)
                
                # Load existing findings, filter out this stream, and append new ones
                tracker_data = load_tracker()
                tracker_data = [f for f in tracker_data if f.get("stream") != inferred_stream]
                
                # Map findings to tracker dictionary format
                for idx, sf in enumerate(scanned_findings, 1):
                    # Unique ID prefixing
                    prefix = "ZC"
                    if sf.category.value == "auth":
                        prefix = "AUTH"
                    elif sf.category.value == "secret":
                        prefix = "SEC-KEY"
                    elif sf.category.value == "dependency":
                        prefix = "DEP"
                    elif sf.category.value == "pattern":
                        prefix = "PATTERN"
                        
                    fid = f"{prefix}-{idx:03d}"
                    cat = sf.category.value if hasattr(sf.category, 'value') else str(sf.category)
                    
                    mapped = {
                        "id": fid,
                        "stream": inferred_stream,
                        "scanner": "ZeroClaw CLI Scanner",
                        "severity": sf.severity.name if hasattr(sf.severity, 'name') else str(sf.severity).upper(),
                        "category": cat,
                        "title": sf.title,
                        "file": sf.file_path,
                        "line": sf.line_number,
                        "remediation": sf.remediation,
                        "reasoning_chain": getattr(sf, "reasoning_chain", None),
                        "fixed_code": getattr(sf, "fixed_code", None),
                        "status": "Open",
                        "timestamp": datetime.now().isoformat(),
                        "remediation_enabled": enable_enrichment  # Persist the toggle state
                    }
                    tracker_data.append(mapped)
                    
                save_tracker(tracker_data)
                
                # Cleanup temporary clone directory if created
                if "zeroclaw_clone_" in str(resolved_target) and resolved_target.exists():
                    try:
                        for root, dirs, files in os.walk(resolved_target):
                            for d in dirs:
                                os.chmod(os.path.join(root, d), stat.S_IWRITE)
                            for f in files:
                                os.chmod(os.path.join(root, f), stat.S_IWRITE)
                        shutil.rmtree(resolved_target, ignore_errors=True)
                    except Exception:
                        pass

                scan_placeholder.empty()
                st.success(f"🎉 Scan completed! Assigned automatically to stream '{inferred_stream}'. Found {len(scanned_findings)} findings.")
                
                # Reload UI state
                st.session_state.findings, _ = load_all_findings()
                st.session_state.active_stream = inferred_stream
                st.rerun()
                
        except Exception as e:
            scan_placeholder.empty()
            st.error(f"Scan execution failed: {e}")

st.markdown("<br>", unsafe_allow_html=True)

# ── Filter findings ───────────────────────────────────────────────────────────
filtered = [
    f for f in st.session_state.findings
    if f["stream"] in sel_streams
    and f["severity"] in sel_severities
    and f["status"] in sel_statuses
] if st.session_state.findings else []

# ── Summary metrics ───────────────────────────────────────────────────────────
total    = len(filtered)
critical = len([f for f in filtered if f["severity"] == "CRITICAL"])
high     = len([f for f in filtered if f["severity"] == "HIGH"])
medium   = len([f for f in filtered if f["severity"] == "MEDIUM"])
open_    = len([f for f in filtered if f["status"] in ("Open", "Fixed (unverified)")])
fixed_v  = len([f for f in filtered if f["status"] in ("Fixed","Verified")])

c1,c2,c3,c4,c5,c6 = st.columns(6)
for col, val, label, color in [
    (c1, total,    "Total Findings",  "#F1F5F9"),
    (c2, critical, "Critical",        "#F87171"),
    (c3, high,     "High",            "#FB923C"),
    (c4, medium,   "Medium",          "#FBBF24"),
    (c5, open_,    "Unresolved",      "#F87171"),
    (c6, fixed_v,  "Fixed / Verified","#34D399"),
]:
    with col:
        st.markdown(f'<div class="metric-card"><div class="metric-number" style="color:{color}">{val}</div><div class="metric-label">{label}</div></div>', unsafe_allow_html=True)

# ── Tabs ──────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4 = st.tabs(["📋 Findings Tracker", "🏆 Scorecard", "📡 Scan Sources", "📥 Export"])

# ── TAB 1: Findings ───────────────────────────────────────────────────────────
with tab1:
    st.markdown(f'<div class="section-header">Findings ({len(filtered)})</div>', unsafe_allow_html=True)

    if not filtered:
        st.markdown('<div style="color:#64748B;padding:40px;text-align:center;background:#111827;border-radius:10px;border:1px dashed #1E2A45;">No findings match your current filters.</div>', unsafe_allow_html=True)
    else:
        sev_emoji   = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵"}
        sev_badges  = {"CRITICAL":'<span class="badge-critical">CRIT</span>',"HIGH":'<span class="badge-high">HIGH</span>',"MEDIUM":'<span class="badge-medium">MED</span>',"LOW":'<span class="badge-low">LOW</span>'}
        
        for f in filtered:
            # Find the original index in session state to update
            idx = next(i for i, x in enumerate(st.session_state.findings) if x["id"] == f["id"])
            
            badge  = sev_badges.get(f["severity"], "")
            emoji  = sev_emoji.get(f["severity"], "⚪")
            sc     = STREAM_META.get(f["stream"], {}).get("color", "#64748B")
            cur_st = f["status"]

            # Format component display
            line_str = f" : L{f['line']}" if f['line'] else ""
            component_display = f"{f['component']}{line_str}"

            with st.expander(f"{emoji}  [{f['id']}]  {f['description'][:70]}...  ·  {f['stream']}  [{cur_st}]"):
                col1, col2 = st.columns([2,1])
                with col1:
                    st.markdown(f"""
                    <div style="margin-bottom:10px;">
                        {badge}
                        <span style="margin-left:8px;font-size:11px;color:{sc};font-weight:600;">● {f['stream']}</span>
                        <span style="margin-left:8px;font-size:11px;color:#475569;">{f['tool']}</span>
                        <span style="margin-left:8px;font-size:11px;color:#334155;">{f['owasp']}</span>
                        <span style="margin-left:8px;font-size:11px;color:#334155;">STRIDE: {f['stride']}</span>
                    </div>
                    <div style="font-family:'JetBrains Mono',monospace;font-size:12px;color:#94A3B8;background:#0A0E1A;padding:8px 12px;border-radius:6px;margin-bottom:10px;">
                        📄 {component_display}
                    </div>
                    <div style="font-size:13px;color:#CBD5E1;margin-bottom:8px;"><b>Vulnerability:</b> {f['description']}</div>
                    """, unsafe_allow_html=True)
                    
                    # Display remediation guidance ONLY if AI Agent enrichment was enabled
                    if f.get("remediation_enabled", True):
                        st.markdown(f"""
                        <div style="background:#0A0E1A;border-left:3px solid #2DD4BF;padding:10px 14px;border-radius:4px;margin-top:8px;margin-bottom:12px;">
                            <div style="font-size:10px;color:#64748B;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:4px;">Remediation Suggestion</div>
                            <div style="font-size:12px;color:#E2E8F0;">{f['steps']}</div>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        # AI Enrichment Details
                        reasoning = f.get("reasoning_chain")
                        is_error = False
                        if reasoning:
                            for indicator in ["non-zero exit", "not found", "timed out", "unavailable", "returned non-zero", "failed", "error"]:
                                if indicator in reasoning.lower():
                                    is_error = True
                                    break
                        if reasoning and not is_error:
                            st.markdown("---")
                            st.markdown("**🧠 ZeroClaw Agent Reasoning:**")
                            st.info(reasoning)
                            
                        if f.get("fixed_code"):
                            st.markdown("**🔧 ZeroClaw Suggested Fix:**")
                            st.code(f["fixed_code"], language="python")
                            
                        # Detailed Remediation Guide MD File Inline Rendering
                        guide_md = get_remediation_guide(f["category"], f["description"])
                        if guide_md:
                            st.markdown("---")
                            st.markdown("### 📘 Detailed Remediation Instructions")
                            st.markdown(guide_md)
                    else:
                        st.markdown("""
                        <div style="color:#64748B;font-size:12px;font-style:italic;margin-top:10px;">
                            ⚠️ ZeroClaw AI Agent Enrichment was disabled for this scan. No remediation tips are available.
                        </div>
                        """, unsafe_allow_html=True)
                        
                with col2:
                    # Dropdown for status selection
                    status_options = ["Open", "Fixed", "Verified", "Fixed (unverified)"]
                    new_status = st.selectbox(
                        "Change Status",
                        status_options,
                        index=status_options.index(cur_st) if cur_st in status_options else 0,
                        key=f"status_select_{f['id']}"
                    )
                    
                    if new_status != cur_st:
                        # Update status
                        st.session_state.findings[idx]["status"] = new_status
                        # Sync back to findings_tracker.json
                        tracker_data = load_tracker()
                        for t_item in tracker_data:
                            if t_item["id"] == f["id"]:
                                t_item["status"] = new_status
                                break
                        save_tracker(tracker_data)
                        
                        # Trigger automated re-scan on transition to Fixed
                        if new_status == "Fixed":
                            with st.spinner("⏳ Re-running scanner to verify fix..."):
                                success, msg = verify_finding(f["id"])
                                if success:
                                    st.toast(f"✅ Fix verified! Finding marked as Verified.", icon="🎉")
                                else:
                                    st.toast(f"❌ Verification failed! Finding marked as Fixed (unverified).", icon="🚨")
                                    
                            # Reload findings
                            st.session_state.findings, _ = load_all_findings()
                            
                        st.rerun()

                    # Trigger manual verification
                    if st.button("🔍 Run Auto-Verification", key=f"verify_btn_{f['id']}", use_container_width=True):
                        with st.spinner("⏳ Re-running scan..."):
                            success, msg = verify_finding(f["id"])
                            if success:
                                st.success(f"🎉 Verified: {msg}")
                            else:
                                st.error(f"🚨 Issue still present: {msg}")
                        # Reload findings
                        st.session_state.findings, _ = load_all_findings()
                        st.rerun()

                    st.markdown(f"""
                    <div style="margin-top:12px;font-size:11px;color:#475569;">
                        <div>🕐 Scanned: {f['timestamp'][:10]}</div>
                        <div style="margin-top:4px;">📦 Repository: {f['repo']}</div>
                    </div>
                    """, unsafe_allow_html=True)

# ── TAB 2: Scorecard ──────────────────────────────────────────────────────────
with tab2:
    st.markdown('<div class="section-header">Stream Security Scorecard</div>', unsafe_allow_html=True)

    stream_stats = {}
    # Extract list of all streams dynamically (including new dynamically inferred ones)
    unique_streams = sorted(list(set(f["stream"] for f in st.session_state.findings)))
    
    # Pre-populate with predefined streams to ensure they exist on scorecard even if clean
    for s_name in STREAM_META.keys():
        if s_name not in unique_streams:
            unique_streams.append(s_name)

    for name in unique_streams:
        stream_findings = [f for f in st.session_state.findings if f["stream"] == name]
        c_count = sum(1 for f in stream_findings if f["severity"] == "CRITICAL" and f["status"] != "Verified")
        h_count = sum(1 for f in stream_findings if f["severity"] == "HIGH" and f["status"] != "Verified")
        m_count = sum(1 for f in stream_findings if f["severity"] == "MEDIUM" and f["status"] != "Verified")
        l_count = sum(1 for f in stream_findings if f["severity"] == "LOW" and f["status"] != "Verified")
        
        # Score Formula: 10.0 minus penalties for active (unverified) findings
        score   = max(0.0, round(10.0 - c_count*3.0 - h_count*2.0 - m_count*1.0 - l_count*0.5, 1))
        
        meta = STREAM_META.get(name, {"color": "#64748B"})
        stream_stats[name] = {"score": score, "C": c_count, "H": h_count, "M": m_count, "L": l_count, "color": meta["color"]}

    # Create scorecard grid
    cols_scorecard = st.columns(min(len(stream_stats), 6))
    for i, (name, stats) in enumerate(stream_stats.items()):
        col_idx = i % len(cols_scorecard)
        sc = "#34D399" if stats["score"] >= 8 else "#FBBF24" if stats["score"] >= 5 else "#F87171"
        bar = int(stats["score"] * 10)
        with cols_scorecard[col_idx]:
            st.markdown(f"""
            <div class="scorecard-card" style="border-top: 3px solid {stats['color']};">
                <div style="font-size:10px;font-weight:600;color:#94A3B8;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:8px;">{name}</div>
                <div style="font-size:30px;font-weight:700;color:{sc};font-family:'JetBrains Mono',monospace;">{stats['score']}</div>
                <div style="font-size:10px;color:#475569;margin-bottom:8px;">/ 10</div>
                <div class="score-bar-bg"><div class="score-bar-fill" style="width:{bar}%;background:{sc};"></div></div>
                <div style="margin-top:10px;font-size:10px;color:#64748B;">
                    {'🟢 Clean' if stats['H']==0 and stats['C']==0 else f"🔴 C:{stats['C']} 🟠 H:{stats['H']} 🟡 M:{stats['M']}"}
                </div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown('<div class="section-header" style="margin-top:32px;">Detailed Scorecard</div>', unsafe_allow_html=True)
    df_score = pd.DataFrame([
        {"Stream": name, "Score /10": stats["score"], "Active Critical": stats["C"], "Active High": stats["H"], "Active Medium": stats["M"], "Active Low": stats["L"]}
        for name, stats in stream_stats.items()
    ]).sort_values("Score /10", ascending=False)
    st.dataframe(df_score, use_container_width=True, hide_index=True)

# ── TAB 3: Scan Sources ───────────────────────────────────────────────────────
with tab3:
    st.markdown('<div class="section-header">Registered Scan Sources</div>', unsafe_allow_html=True)
    st.caption(f"Reading from persistent tracker: `findings_tracker.json` · {len(scan_files)} scan source(s) detected")

    for sf in scan_files:
        sc = STREAM_META.get(sf["stream"], {}).get("color", "#64748B")
        st.markdown(f"""
        <div style="background:#111827;border:1px solid #1E2A45;border-left:3px solid {sc};border-radius:8px;padding:14px 18px;margin-bottom:8px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
                <div>
                    <span style="font-size:13px;font-weight:600;color:#F1F5F9;">{sf['stream']}</span>
                    <span style="margin-left:10px;font-size:11px;color:#475569;font-family:'JetBrains Mono',monospace;">{sf['repo']}</span>
                </div>
                <div style="font-size:11px;color:#64748B;">{sf['timestamp'][:10]} · {sf['tool']} · {sf['env']}</div>
            </div>
            <div style="margin-top:8px;font-size:11px;color:#64748B;">
                Total Findings in Source: {sf['total']} &nbsp;|&nbsp;
                🔴 {sf['critical']} &nbsp;
                🟠 {sf['high']} &nbsp;
                🟡 {sf['medium']} &nbsp;
                🔵 {sf['low']}
            </div>
        </div>
        """, unsafe_allow_html=True)

# ── TAB 4: Export ─────────────────────────────────────────────────────────────
with tab4:
    st.markdown('<div class="section-header">Export Findings</div>', unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**JSON Export** — Export active tracker state")
        export_json = json.dumps(st.session_state.findings, indent=2)
        st.download_button("📥 Download JSON", data=export_json, file_name="findings_tracker_export.json", mime="application/json", use_container_width=True)

    with col2:
        st.markdown("**Markdown Export** — Export summary report")
        md_lines = ["# ZeroClaw Security Findings Report\n", f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n",
                    "| Stream | Severity | ID | Component | Status |\n",
                    "|--------|----------|----|-----------|--------|\n"]
        for f in st.session_state.findings:
            md_lines.append(f"| {f['stream']} | {f['severity']} | {f['id']} | {f['component']} | {f['status']} |\n")
        st.download_button("📄 Download Markdown", data="".join(md_lines), file_name="findings_tracker_report.md", mime="text/markdown", use_container_width=True)

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("""
<div style="text-align:center;color:#1E2A45;font-size:11px;padding:32px 0 8px 0;font-family:'JetBrains Mono',monospace;">
    ZeroClaw Security · Stream 5 · Phase 4 · Amity 2026 Spring Cohort
</div>
""", unsafe_allow_html=True)