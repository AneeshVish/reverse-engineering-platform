"""Controller for proxy-based HTTPS capture: run mitmdump and launch a target app
through it with the mitmproxy CA trusted via environment variables.

For apps the tool launches (Electron/Node/Python/CLI/curl), pointing their TLS
trust at the mitmproxy CA via env vars means we decrypt their HTTPS WITHOUT any
system-wide proxy or certificate install. Native apps that pin certificates or
ignore the env proxy won't be captured this way (honest limitation).
"""

import os
import shutil
import subprocess
import sys

MITM_CA = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")


def mitmdump_path():
    """Find mitmdump — prefer the one next to the running interpreter (our venv)."""
    cand = os.path.join(os.path.dirname(sys.executable), "mitmdump")
    if os.path.isfile(cand):
        return cand
    return shutil.which("mitmdump")


def available():
    return mitmdump_path() is not None


def ca_exists():
    return os.path.isfile(MITM_CA)


def addon_path():
    from src.utils.paths import script_path
    return script_path("mitm_capture_addon")


def capture_env(port, ca=MITM_CA):
    """Env that routes a child process's HTTP(S) through the proxy and trusts the CA."""
    env = os.environ.copy()
    proxy = f"http://127.0.0.1:{port}"
    env.update({
        "HTTP_PROXY": proxy, "HTTPS_PROXY": proxy,
        "http_proxy": proxy, "https_proxy": proxy,
        "ALL_PROXY": proxy, "all_proxy": proxy,
        "NODE_EXTRA_CA_CERTS": ca,     # Electron / Node
        "REQUESTS_CA_BUNDLE": ca,      # Python requests
        "SSL_CERT_FILE": ca,           # Python ssl / many tools
        "CURL_CA_BUNDLE": ca,          # curl
        "GIT_SSL_CAINFO": ca,          # git
    })
    return env


def app_running(name):
    """True if a process whose command matches `name` is already running."""
    if not name:
        return False
    try:
        r = subprocess.run(["pgrep", "-i", "-f", name],
                           capture_output=True, text=True, timeout=5)
        return bool(r.stdout.strip())
    except Exception:
        return False


def resolve_launch_target(path):
    """A .app bundle -> its inner executable; otherwise the path itself."""
    if path and path.rstrip("/").endswith(".app") and os.path.isdir(path):
        try:
            from src.core.bundle_analysis import resolve_app_executable
            exe = resolve_app_executable(path)
            if exe:
                return exe
        except Exception:
            pass
    return path


def start_proxy(port, capture_file):
    """Start mitmdump with the capture addon. Returns the Popen or None."""
    md = mitmdump_path()
    if not md:
        return None
    env = os.environ.copy()
    env["RE_CAPTURE_FILE"] = capture_file
    open(capture_file, "w", encoding="utf-8").close()   # truncate
    return subprocess.Popen(
        [md, "-p", str(port), "-q", "--set", "onboarding=false",
         "-s", addon_path()],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def launch_app(target, port, ca=MITM_CA):
    """Launch the target app/binary wired through the capture proxy. Popen or None."""
    exe = resolve_launch_target(target)
    if not exe or not os.path.exists(exe):
        return None
    return subprocess.Popen([exe], env=capture_env(port, ca),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def run_test_request(port, ca=MITM_CA, url="https://httpbin.org/get?demo=revng"):
    """Fire a sample HTTPS request through the proxy (proves capture works)."""
    curl = shutil.which("curl")
    if not curl:
        return None
    return subprocess.Popen(
        [curl, "-s", "-o", os.devnull, "--max-time", "15", url],
        env=capture_env(port, ca),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
