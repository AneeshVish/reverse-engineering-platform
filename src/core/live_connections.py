"""Live network connections of a running app — the non-googleable signal.

Static analysis can only list hostnames embedded in a binary (which anyone can
also get with `strings` + `dig`). This reads the OS socket table to show what a
RUNNING app is actually connected to right now: real remote IP:port pairs, with
the local source port — specific to this app, this machine, this moment.

Uses `lsof` (works for the current user's own processes without sudo on macOS and
Linux). Returns [] cleanly if lsof is unavailable or the app isn't running.
"""

import shutil
import subprocess


def available():
    return shutil.which("lsof") is not None


def live_connections(app_name, established_only=True, limit=300):
    """Return live TCP connections for processes whose command matches app_name.

    Each item: {command, pid, user, laddr, raddr, state}.
    """
    lsof = shutil.which("lsof")
    if not lsof or not app_name:
        return []
    cmd = [lsof, "-nP", "-iTCP"]
    if established_only:
        cmd += ["-sTCP:ESTABLISHED"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
    except Exception:
        return []

    # lsof truncates the COMMAND column (~9 chars), so match a short key.
    key = app_name.lower()[:9]
    conns = []
    seen = set()
    for line in out.stdout.splitlines()[1:]:
        parts = line.split(None, 8)
        if len(parts) < 9:
            continue
        command, pid, user = parts[0], parts[1], parts[2]
        namecol = parts[8]
        if key not in command.lower():
            continue
        if "->" not in namecol:
            continue
        laddr, rest = namecol.split("->", 1)
        bits = rest.split(" ", 1)
        raddr = bits[0]
        state = ""
        if len(bits) > 1 and "(" in bits[1]:
            state = bits[1].strip().strip("()")
        dedup = (command, laddr, raddr)
        if dedup in seen:
            continue
        seen.add(dedup)
        conns.append({"command": command, "pid": pid, "user": user,
                      "laddr": laddr, "raddr": raddr, "state": state or "ESTABLISHED"})
        if len(conns) >= limit:
            break
    return conns


def format_live_connections(app_name, conns):
    if not conns:
        return (f"LIVE connections: none found.\n"
                f"(Is {app_name} running? lsof only sees your own processes; "
                f"open the app and click Re-analyze.)")
    lines = [f"LIVE connections — what {app_name} is ACTUALLY talking to right now",
             "(read from the OS socket table — NOT DNS; you cannot get this by googling):",
             ""]
    # Group by remote IP for a clean view.
    remotes = {}
    for c in conns:
        remotes.setdefault(c["raddr"], []).append(c)
    for raddr, items in remotes.items():
        locals_ = ", ".join(sorted({i["laddr"] for i in items}))
        lines.append(f"  -> {raddr}   ({items[0]['command']} pid {items[0]['pid']};  local {locals_})")
    return "\n".join(lines)
