"""Controller for proxy-based HTTPS capture: run mitmdump and launch a target app
through it with the mitmproxy CA trusted via environment variables.

For apps the tool launches (Electron/Node/Python/CLI/curl), pointing their TLS
trust at the mitmproxy CA via env vars means we decrypt their HTTPS WITHOUT any
system-wide proxy or certificate install. Native apps that pin certificates or
ignore the env proxy won't be captured this way (honest limitation).
"""

import os
import shutil
import socket
import subprocess
import sys

MITM_CA = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")

# Single, fixed capture port — never surfaced to the user. If it's busy we quietly
# fall back to an OS-assigned free port (still hidden).
DEFAULT_PORT = 8080

# Hosts to PASS THROUGH untouched (TLS not intercepted). These pin their certs and
# BREAK when MITM'd — OS services, software updaters, push. Passing them through
# keeps apps and the OS working; we simply don't decrypt them (we couldn't anyway).
PASSTHROUGH_HOSTS = [
    r"(^|\.)push\.apple\.com",
    r"(^|\.)ocsp\.apple\.com",
    r"(^|\.)ocsp2?\.apple\.com",
    r"(^|\.)gateway\.icloud\.com",
    r"(^|\.)gs-loc\.apple\.com",
    r"(^|\.)mesu\.apple\.com",
    r"(^|\.)mzstatic\.com",
    r"(^|\.)gdmf\.apple\.com",
    r"(^|\.)updates\.discord\.com",
    r"(^|\.)dl\.discordapp\.net",
    r"(^|\.)update\.googleapis\.com",
    # Discord pins its API/gateway — interception only breaks it, never decrypts.
    # Pass it through so the app keeps working instead of failing to load.
    r"(^|\.)discord\.com",
    r"(^|\.)discordapp\.com",
    r"(^|\.)discordapp\.net",
    r"(^|\.)gateway\.discord\.gg",
    # WhatsApp: pinned transport + E2E content — uncapturable; don't break it.
    r"(^|\.)whatsapp\.net",
    r"(^|\.)whatsapp\.com",
]


def pick_port(preferred=DEFAULT_PORT):
    """Return `preferred` if free, else an OS-assigned free port. Never raises."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", preferred))
            return preferred
    except OSError:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", 0))
                return s.getsockname()[1]
        except OSError:
            return preferred


def quit_app(name):
    """Best-effort quit a running app so we can relaunch it under the proxy."""
    if not name:
        return
    if sys.platform == "darwin":
        try:
            subprocess.run(["osascript", "-e", f'quit app "{name}"'],
                           capture_output=True, timeout=8)
        except Exception:
            pass
    try:
        subprocess.run(["pkill", "-i", "-f", name], capture_output=True, timeout=5)
    except Exception:
        pass


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


def ca_trusted():
    """True if the mitmproxy CA is present in the System keychain (i.e. trusted).

    When this is False, intercepted HTTPS shows 'not secure' and clients refuse the
    connection — so capture yields nothing. Used to warn the user up front.
    """
    if sys.platform != "darwin" or not ca_exists():
        return False
    try:
        r = subprocess.run(
            ["security", "find-certificate", "-c", "mitmproxy",
             "/Library/Keychains/System.keychain"],
            capture_output=True, text=True, timeout=8)
        return r.returncode == 0 and "mitmproxy" in (r.stdout + r.stderr).lower()
    except Exception:
        return False


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


def wait_until_stopped(name, timeout=8.0, interval=0.4):
    """Block until no process matching `name` is running, or timeout. Returns True if stopped.

    Single-instance apps (Electron: Claude/Slack/VS Code) hand a relaunch off to the
    already-running instance and exit — so the process we start is NOT the one making
    the API calls, and capture stays empty. Cold-starting requires the old instance
    to fully die first; this polls for that instead of guessing with a fixed sleep.
    """
    import time as _time
    deadline = _time.time() + timeout
    while _time.time() < deadline:
        if not app_running(name):
            return True
        _time.sleep(interval)
    return not app_running(name)


def primary_network_service():
    """The macOS network service (e.g. 'Wi-Fi') backing the default route."""
    try:
        out = subprocess.run(["route", "-n", "get", "default"],
                             capture_output=True, text=True, timeout=5).stdout
        iface = ""
        for ln in out.splitlines():
            if "interface:" in ln:
                iface = ln.split(":", 1)[1].strip()
        hp = subprocess.run(["networksetup", "-listallhardwareports"],
                            capture_output=True, text=True, timeout=5).stdout
        for block in hp.split("\n\n"):
            if f"Device: {iface}" in block:
                for ln in block.splitlines():
                    if ln.startswith("Hardware Port:"):
                        return ln.split(":", 1)[1].strip()
    except Exception:
        pass
    return "Wi-Fi"


def _admin_run(cmds, prompt="Reverse-engineering platform wants to set up traffic capture"):
    """Run privileged shell commands via one native admin prompt. (ok, output)."""
    joined = " ; ".join(cmds)
    script = (f'do shell script "{joined.replace(chr(34), chr(92) + chr(34))}" '
              f'with prompt "{prompt}" with administrator privileges')
    try:
        r = subprocess.run(["osascript", "-e", script],
                           capture_output=True, text=True, timeout=120)
        return r.returncode == 0, (r.stdout + r.stderr)
    except Exception as e:
        return False, str(e)


def enable_system_capture(port, service=None, ca=MITM_CA):
    """Trust the CA + point the system proxy at us — captures ALL non-pinned apps.

    One admin prompt. Returns (ok, service, output). Reverse with
    disable_system_capture(service).
    """
    service = service or primary_network_service()
    ok, out = _admin_run([
        f"security add-trusted-cert -d -r trustRoot "
        f"-k /Library/Keychains/System.keychain '{ca}'",
        f"networksetup -setwebproxy '{service}' 127.0.0.1 {port}",
        f"networksetup -setsecurewebproxy '{service}' 127.0.0.1 {port}",
    ])
    return ok, service, out


def disable_system_capture(service):
    """Revert the system proxy (the CA stays trusted for next time). (ok, output)."""
    if not service:
        return True, ""
    return _admin_run([
        f"networksetup -setwebproxystate '{service}' off",
        f"networksetup -setsecurewebproxystate '{service}' off",
    ], prompt="Reverse-engineering platform wants to stop traffic capture")


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


def _bundle_root(path):
    """Given a .app path OR an executable inside one, return the .app root (or '')."""
    if not path:
        return ""
    p = path.rstrip("/")
    if p.endswith(".app") and os.path.isdir(p):
        return p
    marker = ".app/Contents/MacOS/"
    i = p.find(marker)
    if i >= 0:
        return p[:i + 4]   # include ".app"
    return ""


def is_electron_app(path):
    """True if `path` (a .app or its inner exe) is an Electron/Chromium app.

    Detected by the presence of the Electron Framework in the bundle. Chromium's
    network service — which handles the app's real API traffic — ignores the
    HTTP_PROXY env var, so these apps need Chromium proxy SWITCHES instead.
    """
    root = _bundle_root(path)
    if not root:
        return False
    fw = os.path.join(root, "Contents", "Frameworks", "Electron Framework.framework")
    return os.path.isdir(fw)


def chromium_capture_args(port):
    """Chromium command-line switches that route the app's network service through
    our proxy and make it accept the interception CA.

    - --proxy-server: Chromium (unlike Node) only honors an explicit proxy switch
      or the system proxy, never HTTP_PROXY. This is why the chat traffic slipped
      past the env-var proxy entirely.
    - --ignore-certificate-errors: accept the mitmproxy cert, defeating
      verifier-level cert pinning (app-level pinning in JS/native still won't
      decrypt — that's the Frida/Runtime-Crypto case).

    Chromium bypasses loopback by default, so local IPC is undisturbed.
    """
    return [
        f"--proxy-server=http://127.0.0.1:{port}",
        "--ignore-certificate-errors",
    ]


def start_proxy(port, capture_file, ignore_hosts=None, extra_args=None):
    """Start mitmdump with the capture addon. Returns the Popen or None.

    `ignore_hosts` adds extra host regexes to pass through untouched (on top of
    PASSTHROUGH_HOSTS) — pinned endpoints that would otherwise break the app.
    `extra_args` optional extra mitmdump CLI args (e.g. streaming mode).
    """
    md = mitmdump_path()
    if not md:
        return None
    env = os.environ.copy()
    env["RE_CAPTURE_FILE"] = capture_file
    open(capture_file, "w", encoding="utf-8").close()   # truncate
    cmd = [md, "-p", str(port), "-q", "--set", "onboarding=false", "-s", addon_path()]
    try:
        from src.core.streaming_capture import mitm_streaming_args
        cmd += mitm_streaming_args()
    except ImportError:
        cmd += ["--set", "stream_large_bodies=1048576"]
    if extra_args:
        cmd += list(extra_args)
    hosts = list(PASSTHROUGH_HOSTS) + list(ignore_hosts or [])
    if hosts:
        cmd += ["--ignore-hosts", "(" + "|".join(hosts) + ")"]
    return subprocess.Popen(
        cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def launch_app(target, port, ca=MITM_CA):
    """Launch the target app/binary wired through the capture proxy. Popen or None.

    For Electron/Chromium apps we ALSO pass Chromium proxy + cert switches so the
    network service (which ignores HTTP_PROXY) routes through us — otherwise only
    the Node/undici traffic is captured and the chat/renderer traffic slips past.
    """
    exe = resolve_launch_target(target)
    if not exe or not os.path.exists(exe):
        return None
    argv = [exe]
    if is_electron_app(target) or is_electron_app(exe):
        argv += chromium_capture_args(port)
    return subprocess.Popen(argv, env=capture_env(port, ca),
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
