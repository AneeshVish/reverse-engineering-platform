"""Icon helper backed by qtawesome, with a graceful no-op fallback.

If qtawesome isn't installed the app still runs (icons just become empty), mirroring
the capability-gating philosophy used elsewhere in the project.
"""

from PyQt6.QtGui import QIcon

try:
    import qtawesome as qta
    _HAVE_QTA = True
except Exception:
    qta = None
    _HAVE_QTA = False


# Light neutral that reads on all three (dark) themes. qtawesome renders icons as
# colored pixmaps, so QSS text color can't recolor them — we set it here instead.
DEFAULT_ICON_COLOR = "#aab2d5"


def have_icons():
    return _HAVE_QTA


def set_default_color(color):
    global DEFAULT_ICON_COLOR
    if color:
        DEFAULT_ICON_COLOR = color


def icon(name, color=None):
    """Return a QIcon for a FontAwesome name (e.g. 'fa5s.bug'); empty if unavailable."""
    if not _HAVE_QTA:
        return QIcon()
    try:
        return qta.icon(name, color=color or DEFAULT_ICON_COLOR)
    except Exception:
        return QIcon()
