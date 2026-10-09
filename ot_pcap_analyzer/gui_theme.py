"""
OT PCAP Analyzer - GUI theme and icons
(SVG icon set and theme manager; colours live in gui_style)
"""
try:
    from PyQt5.QtCore import QSettings
    HAS_PYQT5 = True
except ImportError:
    HAS_PYQT5 = False


if HAS_PYQT5:
    from .gui_style import ENGINE, FONT_UI, PALETTES, ThemeEngine

    # =========================================================================
    # SVG ICON SYSTEM - Professional Vector Icons
    # =========================================================================

    class SOCIcons:
        """
        Professional SVG icons for SOC-style UI.
        Using inline SVG for crisp rendering at any scale.
        """

        # Navigation icons (24x24)
        DASHBOARD = '''<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="3" width="7" height="9" rx="1"/>
            <rect x="14" y="3" width="7" height="5" rx="1"/>
            <rect x="14" y="12" width="7" height="9" rx="1"/>
            <rect x="3" y="16" width="7" height="5" rx="1"/>
        </svg>'''

        ASSETS = '''<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
            <line x1="8" y1="21" x2="16" y2="21"/>
            <line x1="12" y1="17" x2="12" y2="21"/>
        </svg>'''

        ATTACK_FLOW = '''<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="5" cy="6" r="3"/>
            <circle cx="19" cy="6" r="3"/>
            <circle cx="12" cy="18" r="3"/>
            <path d="M5 9v3a4 4 0 0 0 4 4h2"/>
            <path d="M19 9v3a4 4 0 0 1-4 4h-2"/>
        </svg>'''

        THREAT_MODEL = '''<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"/>
            <circle cx="12" cy="12" r="6"/>
            <circle cx="12" cy="12" r="2"/>
            <line x1="12" y1="2" x2="12" y2="4"/>
            <line x1="12" y1="20" x2="12" y2="22"/>
            <line x1="4.93" y1="4.93" x2="6.34" y2="6.34"/>
            <line x1="17.66" y1="17.66" x2="19.07" y2="19.07"/>
        </svg>'''

        ANOMALIES = '''<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
            <line x1="12" y1="9" x2="12" y2="13"/>
            <line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>'''

        OT_EVENTS = '''<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="3"/>
            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>
        </svg>'''

        IOC = '''<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="11" cy="11" r="8"/>
            <line x1="21" y1="21" x2="16.65" y2="16.65"/>
            <line x1="11" y1="8" x2="11" y2="14"/>
            <line x1="8" y1="11" x2="14" y2="11"/>
        </svg>'''

        INCIDENTS = '''<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
        </svg>'''

        THREAT_INTEL = '''<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <path d="M9 12l2 2 4-4"/>
        </svg>'''

        HISTORY = '''<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"/>
            <polyline points="12 6 12 12 16 14"/>
        </svg>'''

        # Action icons (20x20)
        IMPORT = '''<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
            <polyline points="17 8 12 3 7 8"/>
            <line x1="12" y1="3" x2="12" y2="15"/>
        </svg>'''

        EXPORT = '''<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
            <polyline points="7 10 12 15 17 10"/>
            <line x1="12" y1="15" x2="12" y2="3"/>
        </svg>'''

        CANCEL = '''<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"/>
            <line x1="15" y1="9" x2="9" y2="15"/>
            <line x1="9" y1="9" x2="15" y2="15"/>
        </svg>'''

        CLOSE = '''<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="18" y1="6" x2="6" y2="18"/>
            <line x1="6" y1="6" x2="18" y2="18"/>
        </svg>'''

        REFRESH = '''<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="23 4 23 10 17 10"/>
            <polyline points="1 20 1 14 7 14"/>
            <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
        </svg>'''

        FILTER = '''<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/>
        </svg>'''

        # Status icons (16x16)
        STATUS_OK = '''<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="20 6 9 17 4 12"/>
        </svg>'''

        STATUS_WARNING = '''<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 2L2 22h20L12 2zm0 6l6 12H6l6-12z"/>
        </svg>'''

        STATUS_ERROR = '''<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">
            <line x1="18" y1="6" x2="6" y2="18"/>
            <line x1="6" y1="6" x2="18" y2="18"/>
        </svg>'''

        STATUS_INFO = '''<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"/>
            <line x1="12" y1="16" x2="12" y2="12"/>
            <line x1="12" y1="8" x2="12.01" y2="8"/>
        </svg>'''

        # Risk level icons
        RISK_CRITICAL = '''<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z" fill="none" stroke="currentColor" stroke-width="2"/>
            <circle cx="12" cy="12" r="4" fill="currentColor"/>
        </svg>'''

        RISK_HIGH = '''<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>
        </svg>'''

        RISK_MEDIUM = '''<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
        </svg>'''

        RISK_LOW = '''<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>'''

        # Device type icons
        DEVICE_SERVER = '''<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="2" y="2" width="20" height="8" rx="2" ry="2"/>
            <rect x="2" y="14" width="20" height="8" rx="2" ry="2"/>
            <line x1="6" y1="6" x2="6.01" y2="6"/>
            <line x1="6" y1="18" x2="6.01" y2="18"/>
        </svg>'''

        DEVICE_PLC = '''<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="4" y="4" width="16" height="16" rx="2"/>
            <circle cx="9" cy="9" r="1.5" fill="currentColor"/>
            <circle cx="15" cy="9" r="1.5" fill="currentColor"/>
            <rect x="7" y="14" width="10" height="3" rx="1"/>
        </svg>'''

        DEVICE_HMI = '''<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="2" y="3" width="20" height="14" rx="2"/>
            <line x1="8" y1="21" x2="16" y2="21"/>
            <line x1="12" y1="17" x2="12" y2="21"/>
            <line x1="6" y1="8" x2="18" y2="8"/>
        </svg>'''

        DEVICE_SENSOR = '''<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 2a3 3 0 0 0-3 3v7a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3z"/>
            <path d="M19 10v2a7 7 0 0 1-14 0v-2"/>
            <line x1="12" y1="19" x2="12" y2="22"/>
        </svg>'''

        DEVICE_NETWORK = '''<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="5" y="11" width="14" height="10" rx="2"/>
            <path d="M12 11V5"/>
            <circle cx="12" cy="5" r="2"/>
            <path d="M6 15h.01"/>
            <path d="M10 15h.01"/>
            <path d="M14 15h.01"/>
            <path d="M18 15h.01"/>
        </svg>'''

        # Protocol icons
        PROTOCOL_MODBUS = '''<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="3" width="18" height="18" rx="2"/>
            <text x="12" y="16" font-size="10" fill="currentColor" text-anchor="middle" font-weight="bold">M</text>
        </svg>'''

        PROTOCOL_ETHERNET = '''<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="11" width="18" height="6" rx="1"/>
            <line x1="7" y1="17" x2="7" y2="21"/>
            <line x1="17" y1="17" x2="17" y2="21"/>
            <line x1="7" y1="7" x2="7" y2="11"/>
            <line x1="17" y1="7" x2="17" y2="11"/>
            <line x1="7" y1="7" x2="17" y2="7"/>
        </svg>'''

        # Misc icons
        ZOOM_IN = '''<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="11" cy="11" r="8"/>
            <line x1="21" y1="21" x2="16.65" y2="16.65"/>
            <line x1="11" y1="8" x2="11" y2="14"/>
            <line x1="8" y1="11" x2="14" y2="11"/>
        </svg>'''

        ZOOM_OUT = '''<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="11" cy="11" r="8"/>
            <line x1="21" y1="21" x2="16.65" y2="16.65"/>
            <line x1="8" y1="11" x2="14" y2="11"/>
        </svg>'''

        THEME_DARK = '''<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
        </svg>'''

        THEME_LIGHT = '''<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="5"/>
            <line x1="12" y1="1" x2="12" y2="3"/>
            <line x1="12" y1="21" x2="12" y2="23"/>
            <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/>
            <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
            <line x1="1" y1="12" x2="3" y2="12"/>
            <line x1="21" y1="12" x2="23" y2="12"/>
            <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/>
            <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
        </svg>'''

        FOLDER = '''<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
        </svg>'''

        FILE = '''<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/>
            <polyline points="13 2 13 9 20 9"/>
        </svg>'''

        PACKETS = '''<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="2" y="7" width="20" height="14" rx="2"/>
            <path d="M16 3h-8v4h8z"/>
            <path d="M6 11h12"/>
            <path d="M6 15h12"/>
        </svg>'''

        TIME = '''<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"/>
            <polyline points="12 6 12 12 16 14"/>
        </svg>'''

        # Mapping for easy access
        NAV_ICONS = {
            "dashboard": DASHBOARD,
            "assets": ASSETS,
            "attack_flow": ATTACK_FLOW,
            "threat_model": THREAT_MODEL,
            "anomalies": ANOMALIES,
            "ot_events": OT_EVENTS,
            "ioc": IOC,
            "incidents": INCIDENTS,
            "threat_intel": THREAT_INTEL,
            "history": HISTORY,
        }

        @staticmethod
        def get_colored_icon(svg: str, color: str) -> str:
            """Return SVG with stroke/fill color applied"""
            return svg.replace('currentColor', color)


        @staticmethod
        def icon(svg: str, color: str, size: int = 18):
            """QIcon rendered from an inline SVG in the given colour."""
            from PyQt5.QtCore import QByteArray, Qt
            from PyQt5.QtGui import QIcon, QPainter, QPixmap
            from PyQt5.QtSvg import QSvgRenderer
            renderer = QSvgRenderer(QByteArray(svg.replace("currentColor", color).encode()))
            icon = QIcon()
            for scale in (1, 2):
                pm = QPixmap(size * scale, size * scale)
                pm.fill(Qt.transparent)
                painter = QPainter(pm)
                renderer.render(painter)
                painter.end()
                pm.setDevicePixelRatio(scale)
                icon.addPixmap(pm)
            return icon

    # =========================================================================
    # THEME MANAGER
    # =========================================================================

    def _legacy_tokens(theme: str) -> dict:
        """Design tokens plus the legacy key names used throughout the views."""
        engine = ThemeEngine(theme)
        p = dict(PALETTES[theme])
        t = engine.token
        p.update({
            "bg_primary": t("app_bg"), "bg_secondary": t("surface"),
            "bg_tertiary": t("surface_2"), "bg_surface": t("surface"),
            "bg_hover": t("hover"), "bg_selected": t("selected"),
            "sidebar_bg": t("surface"), "sidebar_hover": t("hover"),
            "sidebar_active": engine.tint("accent"), "sidebar_border": t("border"),
            "text_primary": t("text"), "text_secondary": t("text_2"),
            "text_tertiary": t("text_3"), "text_muted": t("text_3"),
            "border_light": t("border"), "border_medium": t("border_strong"),
            "border_dark": t("text_3"),
            "risk_critical": t("critical"), "risk_high": t("high"),
            "risk_medium": t("medium"), "risk_low": t("low"), "risk_info": t("info"),
            "risk_critical_bg": engine.tint("critical"), "risk_high_bg": engine.tint("high"),
            "risk_medium_bg": engine.tint("medium"), "risk_low_bg": engine.tint("low"),
            "risk_info_bg": engine.tint("accent"),
            "accent_blue": t("accent"), "accent_purple": t("purple"),
            "accent_green": t("low"), "accent_yellow": t("medium"),
            "accent_red": t("critical"), "accent_cyan": t("cyan"),
            "ot_device": t("purple"), "it_device": t("accent"),
            "unknown_device": t("text_3"),
        })
        return p

    class SOCThemeManager:
        """Holds the active theme (dark / light) and font scale, persisted in QSettings."""

        THEMES = {name: _legacy_tokens(name) for name in PALETTES}

        def __init__(self):
            self.current_theme = "dark"
            self.font_scale = 1.0
            self.settings = QSettings("OTAnalyzer", "SOCGUI")
            self.load_settings()

        def load_settings(self):
            theme = self.settings.value("theme", "dark")
            self.current_theme = theme if theme in self.THEMES else "dark"
            try:
                self.font_scale = float(self.settings.value("font_scale", 1.0))
            except (TypeError, ValueError):
                self.font_scale = 1.0
            ENGINE.set_theme(self.current_theme)

        def save_settings(self):
            self.settings.setValue("theme", self.current_theme)
            self.settings.setValue("font_scale", self.font_scale)

        def toggle_theme(self):
            self.set_theme("light" if self.current_theme == "dark" else "dark")

        def set_theme(self, theme_name: str):
            if theme_name in self.THEMES:
                self.current_theme = theme_name
                ENGINE.set_theme(theme_name)
                self.save_settings()

        def set_font_scale(self, scale: float):
            self.font_scale = max(0.8, min(1.5, scale))
            self.save_settings()

        def get_color(self, color_key: str) -> str:
            return self.THEMES[self.current_theme].get(color_key, "#000000")

        def scale_font(self, base_size: int) -> int:
            return int(base_size * self.font_scale)

        def get_stylesheet(self) -> str:
            """Application-wide style sheet built from the design tokens."""
            t = self.THEMES[self.current_theme]
            fs = self.scale_font
            accent_soft = t["sidebar_active"]
            return f"""
            QWidget {{
                font-family: {FONT_UI};
                font-size: {fs(13)}px;
                color: {t['text']};
            }}
            QMainWindow, QStackedWidget, QDialog, QWidget#Page {{ background-color: {t['app_bg']}; }}
            QScrollArea > QWidget#qt_scrollarea_viewport {{ background: transparent; }}
            QToolTip {{
                background-color: {t['surface_2']}; color: {t['text']};
                border: 1px solid {t['border_strong']}; border-radius: 6px; padding: 6px 8px;
            }}

            /* ---------- sidebar ---------- */
            QWidget#Sidebar {{ background-color: {t['surface']}; border-right: 1px solid {t['border']}; }}
            QWidget#Sidebar QScrollArea, QWidget#Sidebar QScrollArea > QWidget > QWidget {{
                background: transparent; border: none;
            }}
            QLabel#AppTitle {{ font-size: {fs(15)}px; font-weight: 700; color: {t['text']}; }}
            QLabel#AppSubtitle {{ font-size: {fs(11)}px; color: {t['text_3']}; }}
            QLabel#AppLogo {{
                background-color: {t['accent']}; color: {t['on_accent']};
                border-radius: 9px; font-weight: 800; font-size: {fs(12)}px;
            }}
            QLabel#NavSection {{
                font-size: {fs(10)}px; font-weight: 700; letter-spacing: 1px;
                color: {t['text_3']}; padding: 14px 14px 4px 14px; background: transparent;
            }}
            QPushButton#NavItem {{
                background-color: transparent; border: none; border-radius: 8px;
                color: {t['text_2']}; font-size: {fs(13)}px; font-weight: 500;
                text-align: left; padding: 8px 12px; margin: 1px 10px; min-height: 22px;
            }}
            QPushButton#NavItem:hover {{ background-color: {t['hover']}; color: {t['text']}; }}
            QPushButton#NavItem:checked {{
                background-color: {accent_soft}; color: {t['accent']}; font-weight: 600;
            }}
            QPushButton#SidebarTool {{
                background-color: transparent; border: 1px solid {t['border']}; border-radius: 8px;
                color: {t['text_2']}; padding: 6px 10px; min-height: 18px; font-size: {fs(12)}px;
            }}
            QPushButton#SidebarTool:hover {{ background-color: {t['hover']}; color: {t['text']}; }}
            QPushButton#ThemeSeg {{
                background-color: transparent; border: none; border-radius: 6px;
                color: {t['text_2']}; padding: 6px 8px; font-size: {fs(12)}px; min-height: 16px;
            }}
            QPushButton#ThemeSeg:checked {{ background-color: {t['surface']}; color: {t['text']}; font-weight: 600; }}
            QFrame#ThemeSwitch {{ background-color: {t['surface_2']}; border: 1px solid {t['border']}; border-radius: 8px; }}

            /* ---------- top bar ---------- */
            QWidget#TopBar {{ background-color: {t['surface']}; border-bottom: 1px solid {t['border']}; }}
            QLabel#FileChip {{
                background-color: {t['surface_2']}; border: 1px solid {t['border']}; border-radius: 12px;
                color: {t['text_2']}; padding: 3px 10px; font-size: {fs(12)}px;
            }}

            /* ---------- buttons ---------- */
            QPushButton {{
                background-color: {t['surface']}; color: {t['text']};
                border: 1px solid {t['border_strong']}; border-radius: 8px;
                padding: 7px 14px; font-weight: 500; font-size: {fs(13)}px; min-height: 20px;
            }}
            QPushButton:hover {{ background-color: {t['hover']}; border-color: {t['accent']}; }}
            QPushButton:pressed {{ background-color: {t['selected']}; }}
            QPushButton:disabled {{ color: {t['text_3']}; border-color: {t['border']}; background-color: {t['surface']}; }}
            QPushButton#BtnPrimary {{
                background-color: {t['accent']}; color: {t['on_accent']}; border: 1px solid {t['accent']};
                font-weight: 600; padding: 7px 18px;
            }}
            QPushButton#BtnPrimary:hover {{ background-color: {t['accent_hover']}; border-color: {t['accent_hover']}; }}
            QPushButton#BtnDanger {{ color: {t['critical']}; border-color: {t['risk_critical_bg']}; }}
            QPushButton#BtnDanger:hover {{ background-color: {t['risk_critical_bg']}; border-color: {t['critical']}; }}
            QPushButton#BtnDanger:disabled {{ color: {t['text_3']}; border-color: {t['border']}; }}
            QPushButton#BtnSuccess {{ color: {t['low']}; }}
            QPushButton#BtnSuccess:hover {{ background-color: {t['risk_low_bg']}; border-color: {t['low']}; }}
            QPushButton#BtnGhost {{ background-color: transparent; border-color: transparent; color: {t['text_2']}; }}
            QPushButton#BtnGhost:hover {{ background-color: {t['hover']}; color: {t['text']}; }}

            /* ---------- cards ---------- */
            QFrame#MetricCard, QFrame#Card {{
                background-color: {t['surface']}; border: 1px solid {t['border']}; border-radius: 12px;
            }}
            QFrame#MetricCard:hover {{ border-color: {t['border_strong']}; }}
            QLabel#SectionTitle {{
                color: {t['text_3']}; font-size: {fs(11)}px; font-weight: 600; letter-spacing: 0.6px;
                background: transparent;
            }}
            QLabel#PageTitle {{ font-size: {fs(20)}px; font-weight: 700; color: {t['text']}; }}
            QLabel#PageSubtitle {{ font-size: {fs(12)}px; color: {t['text_3']}; }}
            QLabel#ValueLarge {{ color: {t['text']}; font-size: {fs(28)}px; font-weight: 700; }}
            QLabel#ValueMedium {{ color: {t['text']}; font-size: {fs(18)}px; font-weight: 600; }}
            QLabel#Muted {{ color: {t['text_3']}; }}
            QLabel#RiskCritical, QLabel#RiskHigh, QLabel#RiskMedium, QLabel#RiskLow {{
                padding: 3px 8px; border-radius: 6px; font-weight: 600; font-size: {fs(11)}px;
            }}
            QLabel#RiskCritical {{ background-color: {t['risk_critical_bg']}; color: {t['critical']}; }}
            QLabel#RiskHigh {{ background-color: {t['risk_high_bg']}; color: {t['high']}; }}
            QLabel#RiskMedium {{ background-color: {t['risk_medium_bg']}; color: {t['medium']}; }}
            QLabel#RiskLow {{ background-color: {t['risk_low_bg']}; color: {t['low']}; }}

            /* ---------- tables ---------- */
            QTableWidget, QTableView, QTreeWidget, QTreeView, QListWidget, QListView {{
                background-color: {t['surface']};
                alternate-background-color: {t['surface_2']};
                border: 1px solid {t['border']}; border-radius: 10px;
                gridline-color: transparent;
                selection-background-color: {t['selected']}; selection-color: {t['text']};
                font-size: {fs(13)}px; outline: none;
            }}
            QTableWidget::item, QTableView::item {{ padding: 6px 10px; border-bottom: 1px solid {t['border']}; }}
            QTableWidget::item:selected, QTableView::item:selected,
            QTreeView::item:selected, QListView::item:selected {{
                background-color: {t['selected']}; color: {t['text']};
            }}
            QTableWidget::item:hover, QTableView::item:hover {{ background-color: {t['hover']}; }}
            QHeaderView {{ background-color: transparent; border: none; }}
            QHeaderView::section {{
                background-color: {t['surface_2']}; color: {t['text_3']};
                padding: 8px 10px; border: none; border-bottom: 1px solid {t['border']};
                font-weight: 600; font-size: {fs(11)}px; text-transform: uppercase;
            }}
            QTableCornerButton::section {{ background-color: {t['surface_2']}; border: none; }}
            QHeaderView::section:vertical {{
                background-color: transparent; color: {t['text_3']}; border: none;
                padding: 0 8px; font-weight: 500; text-transform: none;
            }}

            /* ---------- inputs ---------- */
            QTextEdit, QPlainTextEdit, QTextBrowser {{
                background-color: {t['surface']}; border: 1px solid {t['border']}; border-radius: 10px;
                padding: 10px; color: {t['text']}; font-size: {fs(13)}px;
                selection-background-color: {t['selected']};
            }}
            QLineEdit, QSpinBox, QDoubleSpinBox {{
                background-color: {t['surface']}; border: 1px solid {t['border_strong']}; border-radius: 8px;
                padding: 6px 10px; color: {t['text']}; font-size: {fs(13)}px;
                selection-background-color: {t['selected']};
            }}
            QLineEdit:focus, QSpinBox:focus, QComboBox:focus {{ border-color: {t['accent']}; }}
            QComboBox {{
                background-color: {t['surface']}; border: 1px solid {t['border_strong']}; border-radius: 8px;
                padding: 6px 10px; color: {t['text']}; font-size: {fs(13)}px; min-width: 110px;
            }}
            QComboBox:hover {{ border-color: {t['accent']}; }}
            QComboBox::drop-down {{ border: none; width: 22px; }}
            QComboBox QAbstractItemView {{
                background-color: {t['surface']}; border: 1px solid {t['border_strong']};
                selection-background-color: {t['selected']}; selection-color: {t['text']}; padding: 4px;
            }}
            QCheckBox {{ spacing: 8px; color: {t['text']}; background: transparent; }}
            QCheckBox::indicator {{
                width: 16px; height: 16px; border-radius: 4px;
                border: 1px solid {t['border_strong']}; background-color: {t['surface']};
            }}
            QCheckBox::indicator:checked {{ background-color: {t['accent']}; border-color: {t['accent']}; }}

            /* ---------- progress ---------- */
            QProgressBar {{
                border: none; border-radius: 4px; text-align: center;
                background-color: {t['surface_2']}; color: {t['text_2']};
                font-size: {fs(10)}px; min-height: 8px; max-height: 8px;
            }}
            QProgressBar::chunk {{ background-color: {t['accent']}; border-radius: 4px; }}

            /* ---------- scrollbars ---------- */
            QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
            QScrollBar::handle:vertical {{ background: {t['border_strong']}; border-radius: 4px; min-height: 30px; }}
            QScrollBar::handle:vertical:hover {{ background: {t['text_3']}; }}
            QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
            QScrollBar::handle:horizontal {{ background: {t['border_strong']}; border-radius: 4px; min-width: 30px; }}
            QScrollBar::handle:horizontal:hover {{ background: {t['text_3']}; }}
            QScrollBar::add-line, QScrollBar::sub-line, QScrollBar::add-page, QScrollBar::sub-page {{
                border: none; background: none; width: 0; height: 0;
            }}
            QScrollArea {{ background: transparent; border: none; }}

            /* ---------- splitters, tabs, groups ---------- */
            QSplitter::handle {{ background-color: {t['border']}; }}
            QSplitter::handle:horizontal {{ width: 1px; }}
            QSplitter::handle:vertical {{ height: 1px; }}
            QTabWidget::pane {{
                border: 1px solid {t['border']}; border-radius: 10px; background-color: {t['surface']};
                top: -1px;
            }}
            QTabBar::tab {{
                background-color: transparent; color: {t['text_2']}; padding: 8px 16px;
                border: none; border-bottom: 2px solid transparent; font-weight: 500; font-size: {fs(12)}px;
            }}
            QTabBar::tab:selected {{ color: {t['accent']}; border-bottom: 2px solid {t['accent']}; }}
            QTabBar::tab:hover {{ color: {t['text']}; }}
            QGroupBox {{
                background-color: {t['surface']}; border: 1px solid {t['border']}; border-radius: 12px;
                margin-top: 22px; padding: 14px 12px 12px 12px; font-weight: 600; font-size: {fs(13)}px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin; subcontrol-position: top left;
                left: 4px; padding: 0 6px; color: {t['text_2']};
            }}
            QWidget#DetailPanel {{ background-color: {t['surface']}; border-left: 1px solid {t['border']}; }}
            QLabel {{ background: transparent; }}
            QMenu {{
                background-color: {t['surface']}; border: 1px solid {t['border_strong']};
                border-radius: 8px; padding: 4px;
            }}
            QMenu::item {{ padding: 6px 18px; border-radius: 6px; }}
            QMenu::item:selected {{ background-color: {t['hover']}; }}
            QMessageBox {{ background-color: {t['surface']}; }}
            QStatusBar {{ background-color: {t['surface']}; color: {t['text_3']}; border-top: 1px solid {t['border']}; }}

            /* ---------- non-native file dialog ---------- */
            QFileDialog {{ background-color: {t['surface']}; }}
            QFileDialog QListView, QFileDialog QTreeView {{ border-radius: 8px; }}
            QFileDialog QToolButton {{
                background-color: {t['surface_2']}; border: 1px solid {t['border']};
                border-radius: 6px; padding: 4px;
            }}
            """
