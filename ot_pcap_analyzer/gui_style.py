"""
OT PCAP Analyzer - theme engine
===============================

One place that decides every colour on screen.

* ``PALETTES`` holds the two modern themes (``dark`` and ``light``) as
  semantic design tokens (surfaces, text tiers, borders, severity colours).
* Many widgets were written with hard-coded colours from the original dark
  palette. Instead of threading theme objects through ~250 inline style
  sheets, :class:`ThemeEngine` *translates* those legacy colours to the
  current theme: each hex value is classified by the CSS property it is used
  in (background / border / text) and by its lightness and hue, then mapped to
  the matching token. New code should use :func:`token` directly.
* :func:`install` hooks ``setStyleSheet``/``setHtml``/table-item colours once
  at start-up, and :func:`apply_theme` re-applies everything when the user
  switches theme, so the whole UI follows the toggle.
"""

from __future__ import annotations

import colorsys
import re
from typing import Dict, Optional

# =============================================================================
# DESIGN TOKENS
# =============================================================================

PALETTES: Dict[str, Dict[str, str]] = {
    "dark": {
        "name": "Dark",
        # surfaces (back to front)
        "app_bg": "#0b1220",
        "surface": "#111a2b",
        "surface_2": "#16213a",
        "hover": "#1d2a45",
        "selected": "#1e3a6e",
        "border": "#22304a",
        "border_strong": "#33456a",
        # text tiers
        "text": "#e8eef7",
        "text_2": "#a9b5c8",
        "text_3": "#7a879c",
        "on_accent": "#ffffff",
        # brand / semantic
        "accent": "#4f8cff",
        "accent_hover": "#6d9fff",
        "critical": "#f87171",
        "high": "#fb923c",
        "medium": "#fbbf24",
        "low": "#34d399",
        "info": "#60a5fa",
        "purple": "#a78bfa",
        "cyan": "#22d3ee",
        "shadow": "rgba(0, 0, 0, 0.45)",
    },
    "light": {
        "name": "Light",
        "app_bg": "#f3f5f9",
        "surface": "#ffffff",
        "surface_2": "#f6f8fb",
        "hover": "#eaf0f8",
        "selected": "#dbe7ff",
        "border": "#e2e7ef",
        "border_strong": "#c9d2df",
        "text": "#0f172a",
        "text_2": "#475569",
        "text_3": "#64748b",
        "on_accent": "#ffffff",
        "accent": "#2563eb",
        "accent_hover": "#1d4ed8",
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#b45309",
        "low": "#059669",
        "info": "#0284c7",
        "purple": "#7c3aed",
        "cyan": "#0891b2",
        "shadow": "rgba(15, 23, 42, 0.10)",
    },
}

SEMANTIC = ("critical", "high", "medium", "low", "accent", "purple", "cyan")

# token value -> token name, for both palettes (first theme wins on clashes)
_TOKEN_BY_VALUE: Dict[str, str] = {}
for _pal in PALETTES.values():
    for _name, _value in _pal.items():
        if isinstance(_value, str) and _value.startswith("#") and _name != "name":
            _TOKEN_BY_VALUE.setdefault(_value.lower(), _name)

FONT_UI = "'Inter', 'Segoe UI', 'Ubuntu', 'Noto Sans', 'Cantarell', 'DejaVu Sans', sans-serif"
FONT_MONO = "'JetBrains Mono', 'Cascadia Code', 'Ubuntu Mono', 'DejaVu Sans Mono', monospace"


# =============================================================================
# COLOUR HELPERS
# =============================================================================

_HEX_RE = re.compile(r"#([0-9a-fA-F]{8}|[0-9a-fA-F]{6}|[0-9a-fA-F]{3})\b")


def _rgb(hex6: str):
    return tuple(int(hex6[i:i + 2], 16) / 255.0 for i in (0, 2, 4))


def _hex(rgb) -> str:
    return "#" + "".join(f"{max(0, min(255, round(c * 255))):02x}" for c in rgb)


def blend(fg: str, bg: str, amount: float) -> str:
    """Mix ``amount`` of ``fg`` over ``bg`` (both #rrggbb)."""
    f, b = _rgb(fg.lstrip("#")[:6]), _rgb(bg.lstrip("#")[:6])
    return _hex(tuple(b[i] + (f[i] - b[i]) * amount for i in range(3)))


def _semantic_for_hue(h: float) -> str:
    deg = h * 360
    if deg < 16 or deg >= 340:
        return "critical"
    if deg < 38:
        return "high"
    if deg < 66:
        return "medium"
    if deg < 168:
        return "low"
    if deg < 196:
        return "cyan"
    if deg < 255:
        return "accent"
    return "purple"


# =============================================================================
# THEME ENGINE
# =============================================================================

class ThemeEngine:
    """Maps legacy hard-coded colours to the active palette."""

    BG_PROPS = ("background", "background-color", "alternate-background-color",
                "selection-background-color", "bgcolor")
    BORDER_PROPS = ("border", "border-top", "border-bottom", "border-left", "border-right",
                    "border-color", "gridline-color", "outline")

    def __init__(self, theme: str = "dark"):
        self.theme = theme if theme in PALETTES else "dark"
        self._cache: Dict[tuple, str] = {}

    # ------------------------------------------------------------------ tokens
    @property
    def p(self) -> Dict[str, str]:
        return PALETTES[self.theme]

    def token(self, name: str) -> str:
        return self.p.get(name, self.p["text"])

    def set_theme(self, theme: str):
        if theme in PALETTES and theme != self.theme:
            self.theme = theme
            self._cache.clear()

    @property
    def is_dark(self) -> bool:
        return self.theme == "dark"

    def tint(self, semantic: str, strength: float = None) -> str:
        """Soft background for a semantic colour (badges, highlighted rows)."""
        if strength is None:
            strength = 0.16 if self.is_dark else 0.11
        return blend(self.token(semantic), self.token("surface"), strength)

    # ------------------------------------------------------------ translation
    def map_color(self, hex_value: str, role: str = "auto", on_strong_bg: bool = False) -> str:
        """Translate one legacy colour (``#rgb``, ``#rrggbb`` or ``#rrggbbaa``)."""
        raw = hex_value.lstrip("#")
        if len(raw) == 3:
            raw = "".join(c * 2 for c in raw)
        alpha = raw[6:8] if len(raw) == 8 else ""
        key = (raw[:6].lower(), role, on_strong_bg)
        mapped = self._cache.get(key)
        if mapped is None:
            mapped = self._map6(raw[:6].lower(), role, on_strong_bg)
            self._cache[key] = mapped
        return mapped + alpha

    def _map6(self, rgb6: str, role: str, on_strong_bg: bool) -> str:
        if rgb6 in ("000000",):
            return "#000000"
        r, g, b = _rgb(rgb6)
        h, l, s = colorsys.rgb_to_hls(r, g, b)
        chroma = max(r, g, b) - min(r, g, b)
        if role == "auto":
            role = "fg" if l > 0.6 else "bg"
        # Colours that already are design tokens (of either theme) map to the
        # same token in the active theme.
        name = _TOKEN_BY_VALUE.get("#" + rgb6)
        if name:
            if name == "on_accent":            # pure white: text, or a light surface
                if role == "fg":
                    return self.token("on_accent" if on_strong_bg else "text")
                return self.token("surface") if role == "bg" else self.token("border")
            return self.token(name)
        t = self.token

        if chroma < 0.11:                       # ---- neutral greys
            if role == "fg":
                if on_strong_bg and l > 0.8:
                    return t("on_accent")
                if l >= 0.9 or l < 0.25:
                    return t("text")
                if l >= 0.78:
                    return t("text_2")
                return t("text_3")
            if role == "border":
                return t("border") if l < 0.42 else t("border_strong")
            # background
            if l < 0.14:
                return t("app_bg")
            if l < 0.22:
                return t("surface")
            if l < 0.29:
                return t("surface_2")
            if l < 0.45:
                return t("hover")
            if l < 0.85:
                return t("border_strong")
            return t("surface")                 # legacy light-theme backgrounds

        sem = _semantic_for_hue(h)               # ---- chromatic
        if role == "bg" and (l < 0.3 or l > 0.86):
            return self.tint(sem)               # dark/light tinted backgrounds
        if role == "fg" and l > 0.86:
            return self.token(sem)
        return self.token(sem)

    # css ----------------------------------------------------------------------
    _DECL_RE = re.compile(r"([a-zA-Z-]+)\s*:\s*([^;{}]*)")

    def _translate_block(self, block: str) -> str:
        decls = list(self._DECL_RE.finditer(block))
        strong_bg = False
        for m in decls:
            if m.group(1).lower() in self.BG_PROPS:
                for hm in _HEX_RE.finditer(m.group(2)):
                    v = hm.group(1)
                    v6 = (v * 2 if len(v) == 3 else v)[:6]
                    r, g, b = _rgb(v6)
                    _, l, _ = colorsys.rgb_to_hls(r, g, b)
                    alpha = len(v) == 8 and int(v[6:8], 16) < 0xC0
                    if max(r, g, b) - min(r, g, b) >= 0.25 and 0.3 <= l <= 0.75 and not alpha:
                        strong_bg = True

        def repl(m):
            prop, value = m.group(1), m.group(2)
            pl = prop.lower()
            if pl in self.BG_PROPS:
                role = "bg"
            elif pl.startswith("border") or pl in self.BORDER_PROPS:
                role = "border"
            elif pl in ("color", "selection-color"):
                role = "fg"
            else:
                role = "auto"
            value = _HEX_RE.sub(
                lambda hm: self._qss_color(self.map_color(hm.group(0), role, strong_bg)), value)
            return f"{prop}: {value}"

        return self._DECL_RE.sub(repl, block)

    @staticmethod
    def _qss_color(value: str) -> str:
        """Qt reads 8-digit hex as #AARRGGBB; legacy code meant CSS #RRGGBBAA."""
        if len(value) == 9:
            r, g, b, a = (int(value[i:i + 2], 16) for i in (1, 3, 5, 7))
            return f"rgba({r}, {g}, {b}, {a})"
        return value

    def _opaque(self, value: str) -> str:
        """Flatten #RRGGBBAA over the surface colour (Qt rich text has no alpha)."""
        if len(value) == 9:
            return blend(value[:7], self.token("surface"), int(value[7:9], 16) / 255)
        return value

    def translate_css(self, css: str) -> str:
        if not css or "#" not in css:
            return css
        if "{" not in css:
            return self._translate_block(css)
        return re.sub(r"\{([^{}]*)\}", lambda m: "{" + self._translate_block(m.group(1)) + "}", css)

    # html ---------------------------------------------------------------------
    _STYLE_ATTR_RE = re.compile(r"""style\s*=\s*(['"])(.*?)\1""", re.S | re.I)
    _STYLE_TAG_RE = re.compile(r"(<style[^>]*>)(.*?)(</style>)", re.S | re.I)
    _ATTR_COLOR_RE = re.compile(r"""\b(bgcolor|color)\s*=\s*(['"])(#[0-9a-fA-F]{3,8})\2""", re.I)

    def translate_html(self, html: str) -> str:
        if not html or "#" not in html:
            return html
        prev, self._qss_color = self._qss_color, self._opaque
        try:
            return self._translate_html(html)
        finally:
            self._qss_color = prev

    def _translate_html(self, html: str) -> str:
        html = self._STYLE_TAG_RE.sub(lambda m: m.group(1) + self.translate_css(m.group(2)) + m.group(3), html)
        html = self._STYLE_ATTR_RE.sub(
            lambda m: f"style={m.group(1)}{self._translate_block(m.group(2))}{m.group(1)}", html)
        html = self._ATTR_COLOR_RE.sub(
            lambda m: f"{m.group(1)}={m.group(2)}"
                      f"{self._opaque(self.map_color(m.group(3), 'bg' if m.group(1).lower() == 'bgcolor' else 'fg'))}"
                      f"{m.group(2)}", html)
        return html

    # Qt objects ---------------------------------------------------------------
    def qcolor(self, value, role: str = "auto"):
        """QColor for a legacy colour value in the current theme."""
        from PyQt5.QtGui import QColor
        if isinstance(value, str) and value.startswith("#"):
            mapped = self.map_color(value, role)
            c = QColor(mapped[:7])
            if len(mapped) == 9:                # legacy CSS-style #RRGGBBAA
                c.setAlpha(int(mapped[7:9], 16))
            return c
        c = QColor(value)
        if not c.isValid():
            return c
        mapped = QColor(self.map_color(c.name(), role))
        mapped.setAlpha(c.alpha())
        return mapped

    def qpalette(self):
        from PyQt5.QtGui import QColor, QPalette
        t = self.token
        pal = QPalette()
        roles = {
            QPalette.Window: "app_bg", QPalette.WindowText: "text",
            QPalette.Base: "surface", QPalette.AlternateBase: "surface_2",
            QPalette.ToolTipBase: "surface_2", QPalette.ToolTipText: "text",
            QPalette.Text: "text", QPalette.Button: "surface_2", QPalette.ButtonText: "text",
            QPalette.BrightText: "critical", QPalette.Highlight: "accent",
            QPalette.HighlightedText: "on_accent", QPalette.Link: "accent",
            QPalette.PlaceholderText: "text_3", QPalette.Light: "border_strong",
            QPalette.Midlight: "border", QPalette.Mid: "border_strong",
            QPalette.Dark: "app_bg", QPalette.Shadow: "app_bg",
        }
        for role, name in roles.items():
            pal.setColor(role, QColor(t(name)))
        for role in (QPalette.WindowText, QPalette.Text, QPalette.ButtonText):
            pal.setColor(QPalette.Disabled, role, QColor(t("text_3")))
        return pal


# The single engine used by the GUI
ENGINE = ThemeEngine()


def token(name: str) -> str:
    """Colour of a design token in the active theme."""
    return ENGINE.token(name)


def themed(value, role: str = "auto"):
    """QColor of a legacy colour in the active theme (for QPainter/QGraphics code)."""
    return ENGINE.qcolor(value, role)


# =============================================================================
# QT HOOKS
# =============================================================================

_INSTALLED = False
_ORIG = {}

# Box properties of a bare style sheet on a container would otherwise be
# inherited by every child (each label inside a card got its own border).
_BOX_PROPS = re.compile(r"^\s*(border[a-z-]*|background[a-z-]*|padding[a-z-]*|margin[a-z-]*|"
                        r"min-[a-z]+|max-[a-z]+|outline)\s*:", re.I)
_LEAF_TYPES = None


def _scoped(widget, css: str) -> str:
    """Scope box declarations of a bare style sheet to the container itself."""
    global _LEAF_TYPES
    if not css or "{" in css or ":" not in css:
        return css
    if _LEAF_TYPES is None:
        from PyQt5.QtWidgets import (QAbstractButton, QAbstractItemView, QAbstractSlider,
                                     QAbstractSpinBox, QComboBox, QLabel, QLineEdit,
                                     QProgressBar, QTextEdit, QPlainTextEdit, QScrollBar)
        _LEAF_TYPES = (QAbstractButton, QAbstractItemView, QAbstractSlider, QAbstractSpinBox,
                       QComboBox, QLabel, QLineEdit, QProgressBar, QTextEdit, QPlainTextEdit,
                       QScrollBar)
    if isinstance(widget, _LEAF_TYPES):
        return css
    decls = [d.strip() for d in css.split(";") if d.strip()]
    box = [d for d in decls if _BOX_PROPS.match(d)]
    if not box:
        return css
    text = [d for d in decls if not _BOX_PROPS.match(d)]
    name = widget.objectName()
    if not name or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        name = f"w{id(widget):x}"
        widget.setObjectName(name)
    from PyQt5.QtCore import Qt
    widget.setAttribute(Qt.WA_StyledBackground, True)
    out = ""
    if text:
        out += "* { " + "; ".join(text) + "; } "
    return out + f"#{name} {{ " + "; ".join(box) + "; }"


def install():
    """Route colour-setting Qt calls through the engine (idempotent)."""
    global _INSTALLED
    if _INSTALLED:
        return
    from PyQt5.QtGui import QBrush
    from PyQt5.QtWidgets import QLabel, QTableWidgetItem, QTextEdit, QWidget

    _ORIG["setStyleSheet"] = QWidget.setStyleSheet
    _ORIG["setHtml"] = QTextEdit.setHtml
    _ORIG["setText"] = QLabel.setText
    _ORIG["setForeground"] = QTableWidgetItem.setForeground
    _ORIG["setBackground"] = QTableWidgetItem.setBackground

    def set_style_sheet(self, css):
        css = css or ""
        self.setProperty("_theme_css", css)
        _ORIG["setStyleSheet"](self, _scoped(self, ENGINE.translate_css(css)))

    def set_html(self, html):
        self.setProperty("_theme_html", html)
        _ORIG["setHtml"](self, ENGINE.translate_html(html))

    def label_set_text(self, text):
        if text and "<" in text and "#" in text:
            self.setProperty("_theme_html", text)
            text = ENGINE.translate_html(text)
        elif self.property("_theme_html") is not None:
            self.setProperty("_theme_html", None)
        _ORIG["setText"](self, text)

    def _item_color(orig_name, role):
        def setter(self, value):
            if isinstance(value, QBrush):
                value = value.color()
            _ORIG[orig_name](self, ENGINE.qcolor(value, role))
        return setter

    QWidget.setStyleSheet = set_style_sheet
    QTextEdit.setHtml = set_html
    QLabel.setText = label_set_text
    QTableWidgetItem.setForeground = _item_color("setForeground", "fg")
    QTableWidgetItem.setBackground = _item_color("setBackground", "bg")
    _INSTALLED = True


def apply_theme(app, theme: Optional[str] = None):
    """Switch theme and re-colour every existing widget."""
    from PyQt5.QtWidgets import QLabel, QTextEdit
    if theme:
        ENGINE.set_theme(theme)
    app.setPalette(ENGINE.qpalette())
    for w in app.topLevelWidgets():
        w.setPalette(ENGINE.qpalette())
    for w in app.allWidgets():
        css = w.property("_theme_css")
        if css:
            _ORIG.get("setStyleSheet", type(w).setStyleSheet)(w, _scoped(w, ENGINE.translate_css(css)))
        html = w.property("_theme_html")
        if html:
            if isinstance(w, QTextEdit):
                _ORIG.get("setHtml", QTextEdit.setHtml)(w, ENGINE.translate_html(html))
            elif isinstance(w, QLabel):
                _ORIG.get("setText", QLabel.setText)(w, ENGINE.translate_html(html))
