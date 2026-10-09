"""
OT PCAP Analyzer - GUI theme and icons
(SOC icon set and theme manager)
"""
try:
    from PyQt5.QtCore import QSettings
    HAS_PYQT5 = True
except ImportError:
    HAS_PYQT5 = False


if HAS_PYQT5:
    pass

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

    # =========================================================================
    # SOC THEME MANAGER - Professional Dark Theme
    # =========================================================================

    class SOCThemeManager:
        """
        Professional SOC-style theme manager.
        Restrained color system with semantic colors for status.
        """

        THEMES = {
            "dark": {
                "name": "SOC Dark Pro",
                # Base backgrounds - BRIGHTER for better readability
                "bg_primary": "#1c2128",      # Brighter main background
                "bg_secondary": "#252b33",    # Card backgrounds - more visible
                "bg_tertiary": "#3d444d",     # Hover state - visible contrast

                # Legacy aliases for compatibility
                "bg_surface": "#252b33",
                "bg_hover": "#3d444d",
                "bg_selected": "#388bfd40",

                # Sidebar specific - distinct from main content
                "sidebar_bg": "#252b33",      # Darker for contrast with main
                "sidebar_hover": "#3d444d",
                "sidebar_active": "#388bfd30",
                "sidebar_border": "#484f58",

                # Neutral text colors - HIGH CONTRAST
                "text_primary": "#f0f6fc",    # Bright white - very readable
                "text_secondary": "#e6edf3",  # Brighter gray - good contrast
                "text_tertiary": "#a0a8b2",   # Medium gray - still visible
                "text_muted": "#8b949e",

                # Border colors - more visible
                "border_light": "#484f58",
                "border_medium": "#6e7681",
                "border_dark": "#8b949e",

                # Semantic colors (Status) - VIBRANT & BRIGHT
                "risk_critical": "#ff6b6b",   # Bright Red - Critical
                "risk_high": "#ffa94d",       # Bright Orange - High
                "risk_medium": "#ffd43b",     # Bright Yellow - Medium
                "risk_low": "#69db7c",        # Bright Green - Low
                "risk_info": "#74c0fc",       # Bright Blue - Info

                # Semantic backgrounds (25% opacity for better visibility)
                "risk_critical_bg": "#ff6b6b40",
                "risk_high_bg": "#ffa94d40",
                "risk_medium_bg": "#ffd43b35",
                "risk_low_bg": "#69db7c40",
                "risk_info_bg": "#74c0fc40",

                # Accent color - Electric cyan/blue
                "accent": "#58a6ff",          # GitHub blue - highly visible
                "accent_hover": "#79c0ff",    # Lighter on hover

                # Legacy accent aliases - all vibrant
                "accent_blue": "#58a6ff",
                "accent_purple": "#bc8cff",
                "accent_green": "#56d364",
                "accent_yellow": "#e3b341",
                "accent_red": "#f85149",
                "accent_cyan": "#39d5ff",

                # Device colors - bright and distinguishable
                "ot_device": "#bc8cff",       # Bright purple for OT
                "it_device": "#58a6ff",       # Bright blue for IT
                "unknown_device": "#8b949e",  # Gray for unknown

                # Shadow
                "shadow": "rgba(0, 0, 0, 0.6)",
            },

            "light": {
                "name": "SOC Light",
                # Light theme - clean white backgrounds
                "bg_primary": "#ffffff",
                "bg_secondary": "#f6f8fa",
                "bg_tertiary": "#eaeef2",

                "bg_surface": "#f6f8fa",
                "bg_hover": "#eaeef2",
                "bg_selected": "#ddf4ff",

                "sidebar_bg": "#f6f8fa",
                "sidebar_hover": "#eaeef2",
                "sidebar_active": "#ddf4ff",
                "sidebar_border": "#d0d7de",

                "text_primary": "#1f2328",
                "text_secondary": "#424a53",
                "text_tertiary": "#656d76",
                "text_muted": "#8c959f",

                "border_light": "#d0d7de",
                "border_medium": "#afb8c1",
                "border_dark": "#8c959f",

                "risk_critical": "#cf222e",
                "risk_high": "#bf5f04",
                "risk_medium": "#9a6700",
                "risk_low": "#1a7f37",
                "risk_info": "#0969da",

                "risk_critical_bg": "#ffebe9",
                "risk_high_bg": "#fff1e5",
                "risk_medium_bg": "#fff8c5",
                "risk_low_bg": "#dafbe1",
                "risk_info_bg": "#ddf4ff",

                "accent": "#0969da",
                "accent_hover": "#0550ae",
                "accent_blue": "#0969da",
                "accent_purple": "#8250df",
                "accent_green": "#1a7f37",
                "accent_yellow": "#9a6700",
                "accent_red": "#cf222e",
                "accent_cyan": "#0a69da",

                "ot_device": "#8250df",
                "it_device": "#0969da",
                "unknown_device": "#656d76",

                "shadow": "rgba(27, 31, 36, 0.12)",
            }
        }

        def __init__(self):
            self.current_theme = "dark"  # Default to dark SOC theme
            self.font_scale = 1.0
            self.settings = QSettings("OTAnalyzer", "SOCGUI")
            self.load_settings()

        def load_settings(self):
            self.current_theme = self.settings.value("theme", "dark")
            try:
                self.font_scale = float(self.settings.value("font_scale", 1.0))
            except (TypeError, ValueError):
                self.font_scale = 1.0

        def save_settings(self):
            self.settings.setValue("theme", self.current_theme)
            self.settings.setValue("font_scale", self.font_scale)

        def toggle_theme(self):
            self.current_theme = "light" if self.current_theme == "dark" else "dark"
            self.save_settings()

        def set_theme(self, theme_name: str):
            if theme_name in self.THEMES:
                self.current_theme = theme_name
                self.save_settings()

        def set_font_scale(self, scale: float):
            self.font_scale = max(0.8, min(1.5, scale))
            self.save_settings()

        def get_color(self, color_key: str) -> str:
            return self.THEMES[self.current_theme].get(color_key, "#000000")

        def scale_font(self, base_size: int) -> int:
            return int(base_size * self.font_scale)

        def get_stylesheet(self) -> str:
            """Generate SOC-style stylesheet"""
            t = self.THEMES[self.current_theme]
            fs = self.scale_font

            return f"""
            /* ===== GLOBAL SOC STYLES ===== */
            QWidget {{
                font-family: 'JetBrains Mono', 'Consolas', 'SF Mono', monospace;
                font-size: {fs(13)}px;
                color: {t['text_primary']};
            }}

            QMainWindow {{
                background-color: {t['bg_primary']};
            }}

            /* ===== SIDEBAR NAVIGATION (SOC Style) ===== */
            QWidget#Sidebar {{
                background-color: {t['sidebar_bg']};
                border-right: 1px solid {t['sidebar_border']};
            }}

            QListWidget#NavList {{
                background-color: transparent;
                border: none;
                outline: none;
                padding: 8px 0;
            }}

            QListWidget#NavList::item {{
                color: {t['text_secondary']};
                padding: 16px 16px;
                margin: 0 8px;
                border-radius: 4px;
                font-weight: 500;
                font-size: {fs(13)}px;
                border-left: 3px solid transparent;
            }}

            QListWidget#NavList::item:hover {{
                background-color: {t['sidebar_hover']};
                color: {t['text_primary']};
                border-left: 3px solid transparent;
            }}

            QListWidget#NavList::item:selected {{
                background-color: {t['sidebar_active']};
                color: {t['accent']};
                font-weight: 600;
                border-left: 3px solid {t['accent']};
            }}

            /* ===== GROUPED NAVIGATION SECTIONS ===== */
            QLabel#SectionHeader {{
                font-size: {fs(11)}px;
                font-weight: 700;
                letter-spacing: 1px;
                padding: 16px 16px 6px 16px;
                color: {t['text_tertiary']};
                text-transform: uppercase;
            }}

            QPushButton[objectName^="nav_"] {{
                background-color: transparent;
                border: none;
                border-left: 3px solid transparent;
                border-radius: 0;
                color: {t['text_secondary']};
                font-size: {fs(13)}px;
                font-weight: 500;
                text-align: left;
                padding: 16px 16px;
                margin: 0 8px;
            }}

            QPushButton[objectName^="nav_"]:hover {{
                background-color: {t['sidebar_hover']};
                color: {t['text_primary']};
            }}

            QPushButton[objectName^="nav_"]:checked {{
                background-color: {t['sidebar_active']};
                color: {t['accent']};
                font-weight: 600;
                border-left: 3px solid {t['accent']};
            }}

            /* Workflow Section Indicators */
            QLabel#SectionTriage {{
                color: {t['risk_critical']};
            }}
            QLabel#SectionAnalyze {{
                color: {t['accent']};
            }}
            QLabel#SectionThreat {{
                color: {t['risk_high']};
            }}
            QLabel#SectionReport {{
                color: {t['risk_low']};
            }}

            /* ===== TOP BAR (Darker with subtle border) ===== */
            QWidget#TopBar {{
                background-color: {t['sidebar_bg']};
                border-bottom: 1px solid {t['border_light']};
            }}

            /* ===== BUTTONS (Ghost & Primary) ===== */
            QPushButton {{
                background-color: transparent;
                color: {t['text_secondary']};
                border: 1px solid {t['border_light']};
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: 500;
                font-size: {fs(13)}px;
                min-height: 24px;
            }}

            QPushButton:hover {{
                background-color: {t['bg_tertiary']};
                border-color: {t['accent']};
                color: {t['text_primary']};
            }}

            QPushButton:pressed {{
                background-color: {t['bg_selected']};
            }}

            QPushButton:disabled {{
                background-color: transparent;
                color: {t['text_muted']};
                border-color: {t['border_light']};
            }}

            /* Primary Button - Only filled button (Import PCAP) */
            QPushButton#BtnPrimary {{
                background-color: {t['accent']};
                color: white;
                border: none;
                font-weight: 600;
                padding: 8px 24px;
            }}

            QPushButton#BtnPrimary:hover {{
                background-color: {t['accent_hover']};
            }}

            QPushButton#BtnPrimary:disabled {{
                background-color: {t['accent']}50;
            }}

            /* Ghost Danger Button (Cancel) */
            QPushButton#BtnDanger {{
                background-color: transparent;
                color: {t['risk_critical']};
                border: 1px solid {t['risk_critical']}60;
            }}

            QPushButton#BtnDanger:hover {{
                background-color: {t['risk_critical_bg']};
                border-color: {t['risk_critical']};
            }}

            /* Ghost Success Button (Export) */
            QPushButton#BtnSuccess {{
                background-color: transparent;
                color: {t['risk_low']};
                border: 1px solid {t['risk_low']}60;
            }}

            QPushButton#BtnSuccess:hover {{
                background-color: {t['risk_low_bg']};
                border-color: {t['risk_low']};
            }}

            /* ===== KPI/METRIC CARDS (Consistent styling) ===== */
            QFrame#MetricCard {{
                background-color: {t['bg_secondary']};
                border: 1px solid {t['border_light']};
                border-radius: 8px;
                padding: 16px;
            }}

            QFrame#MetricCard:hover {{
                border-color: {t['border_medium']};
            }}

            /* ===== SEVERITY BADGES (Small pills) ===== */
            QLabel#RiskCritical {{
                background-color: {t['risk_critical_bg']};
                color: {t['risk_critical']};
                padding: 4px 8px;
                border-radius: 4px;
                font-weight: 600;
                font-size: {fs(11)}px;
            }}

            QLabel#RiskHigh {{
                background-color: {t['risk_high_bg']};
                color: {t['risk_high']};
                padding: 4px 8px;
                border-radius: 4px;
                font-weight: 600;
                font-size: {fs(11)}px;
            }}

            QLabel#RiskMedium {{
                background-color: {t['risk_medium_bg']};
                color: {t['risk_high']};
                padding: 4px 8px;
                border-radius: 4px;
                font-weight: 600;
                font-size: {fs(11)}px;
            }}

            QLabel#RiskLow {{
                background-color: {t['risk_low_bg']};
                color: {t['risk_low']};
                padding: 4px 8px;
                border-radius: 4px;
                font-weight: 600;
                font-size: {fs(11)}px;
            }}

            /* ===== TABLES (SOC Style) ===== */
            QTableWidget {{
                background-color: {t['bg_secondary']};
                gridline-color: transparent;
                border: 1px solid {t['border_light']};
                border-radius: 8px;
                selection-background-color: {t['bg_selected']};
                font-size: {fs(13)}px;
            }}

            QTableWidget::item {{
                padding: 8px 16px;
                border-bottom: 1px solid {t['bg_primary']};
                color: {t['text_primary']};
            }}

            QTableWidget::item:selected {{
                background-color: {t['accent']}20;
                border-left: 3px solid {t['accent']};
            }}

            QTableWidget::item:hover {{
                background-color: {t['bg_tertiary']};
            }}

            QHeaderView::section {{
                background-color: {t['bg_primary']};
                color: {t['text_secondary']};
                padding: 8px 16px;
                border: none;
                border-bottom: 1px solid {t['border_light']};
                font-weight: 600;
                font-size: {fs(11)}px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}

            /* ===== TEXT AREAS ===== */
            QTextEdit {{
                background-color: {t['bg_secondary']};
                border: 1px solid {t['border_light']};
                border-radius: 8px;
                padding: 16px;
                color: {t['text_primary']};
                font-size: {fs(13)}px;
                line-height: 1.5;
            }}

            /* ===== SEARCH INPUT ===== */
            QLineEdit {{
                background-color: {t['bg_secondary']};
                border: 1px solid {t['border_light']};
                border-radius: 4px;
                padding: 8px 16px;
                color: {t['text_primary']};
                font-size: {fs(13)}px;
            }}

            QLineEdit:focus {{
                border-color: {t['accent']};
            }}

            /* ===== COMBO BOX ===== */
            QComboBox {{
                background-color: {t['bg_secondary']};
                border: 1px solid {t['border_light']};
                border-radius: 4px;
                padding: 8px 16px;
                color: {t['text_primary']};
                font-size: {fs(13)}px;
                min-width: 120px;
            }}

            QComboBox:hover {{
                border-color: {t['accent']};
            }}

            QComboBox::drop-down {{
                border: none;
                padding-right: 8px;
            }}

            QComboBox QAbstractItemView {{
                background-color: {t['bg_secondary']};
                border: 1px solid {t['border_light']};
                border-radius: 4px;
                selection-background-color: {t['accent']}30;
            }}

            /* ===== PROGRESS BAR ===== */
            QProgressBar {{
                border: none;
                border-radius: 5px;
                text-align: center;
                background-color: {t['bg_tertiary']};
                color: {t['text_primary']};
                font-size: {fs(11)}px;
                min-height: 10px;
                max-height: 10px;
            }}

            QProgressBar::chunk {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {t['accent_blue']}, stop:1 {t['accent_purple']});
                border-radius: 5px;
            }}

            /* ===== SCROLLBAR ===== */
            QScrollBar:vertical {{
                background: {t['bg_primary']};
                width: 10px;
                border-radius: 5px;
            }}

            QScrollBar::handle:vertical {{
                background: {t['border_medium']};
                border-radius: 5px;
                min-height: 30px;
            }}

            QScrollBar::handle:vertical:hover {{
                background: {t['border_dark']};
            }}

            QScrollBar:horizontal {{
                background: {t['bg_primary']};
                height: 10px;
                border-radius: 5px;
            }}

            QScrollBar::handle:horizontal {{
                background: {t['border_medium']};
                border-radius: 5px;
                min-width: 30px;
            }}

            QScrollBar::add-line, QScrollBar::sub-line {{
                border: none;
                background: none;
            }}

            /* ===== SPLITTER ===== */
            QSplitter::handle {{
                background-color: {t['border_light']};
            }}

            QSplitter::handle:horizontal {{
                width: 1px;
            }}

            QSplitter::handle:vertical {{
                height: 1px;
            }}

            /* ===== FILE DIALOG (Non-native) - Lighter backgrounds for readability ===== */
            QFileDialog {{
                background-color: {t['bg_tertiary']};
                color: {t['text_primary']};
            }}

            QFileDialog QWidget {{
                background-color: {t['bg_tertiary']};
                color: {t['text_primary']};
            }}

            QFileDialog QListView,
            QFileDialog QTreeView {{
                background-color: {t['bg_hover']};
                alternate-background-color: {t['bg_tertiary']};
                color: {t['text_primary']};
                border: 1px solid {t['border_medium']};
                border-radius: 4px;
                selection-background-color: {t['accent_blue']};
            }}

            QFileDialog QListView::item,
            QFileDialog QTreeView::item {{
                color: {t['text_primary']};
                padding: 6px 4px;
                min-height: 24px;
            }}

            QFileDialog QListView::item:selected,
            QFileDialog QTreeView::item:selected {{
                background-color: {t['accent_blue']};
                color: #ffffff;
            }}

            QFileDialog QListView::item:hover,
            QFileDialog QTreeView::item:hover {{
                background-color: {t['border_medium']};
            }}

            QFileDialog QLabel {{
                color: {t['text_primary']};
                background-color: transparent;
            }}

            QFileDialog QLineEdit {{
                background-color: {t['bg_hover']};
                color: {t['text_primary']};
                border: 1px solid {t['border_medium']};
                border-radius: 4px;
                padding: 6px 10px;
                selection-background-color: {t['accent_blue']};
            }}

            QFileDialog QLineEdit:focus {{
                border-color: {t['accent_blue']};
            }}

            QFileDialog QComboBox {{
                background-color: {t['bg_hover']};
                color: {t['text_primary']};
                border: 1px solid {t['border_medium']};
                border-radius: 4px;
                padding: 6px 10px;
            }}

            QFileDialog QComboBox:hover {{
                border-color: {t['accent_blue']};
            }}

            QFileDialog QComboBox::drop-down {{
                border: none;
                padding-right: 8px;
            }}

            QFileDialog QComboBox QAbstractItemView {{
                background-color: {t['bg_hover']};
                color: {t['text_primary']};
                border: 1px solid {t['border_medium']};
                selection-background-color: {t['accent_blue']};
            }}

            QFileDialog QToolButton {{
                background-color: {t['bg_hover']};
                border: 1px solid {t['border_medium']};
                border-radius: 4px;
                padding: 6px;
                color: {t['text_primary']};
            }}

            QFileDialog QToolButton:hover {{
                background-color: {t['border_medium']};
                border-color: {t['accent_blue']};
            }}

            QFileDialog QPushButton {{
                background-color: {t['bg_hover']};
                color: {t['text_primary']};
                border: 1px solid {t['border_medium']};
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: 500;
            }}

            QFileDialog QPushButton:hover {{
                background-color: {t['border_medium']};
                border-color: {t['accent_blue']};
            }}

            QFileDialog QPushButton:pressed {{
                background-color: {t['accent_blue']};
            }}

            QFileDialog QHeaderView::section {{
                background-color: {t['bg_tertiary']};
                color: {t['text_primary']};
                border: none;
                border-bottom: 1px solid {t['border_medium']};
                padding: 8px;
                font-weight: 600;
            }}

            QFileDialog QSplitter::handle {{
                background-color: {t['border_medium']};
            }}

            QFileDialog QFrame {{
                background-color: {t['bg_tertiary']};
            }}

            /* ===== TABS (for sub-panels) ===== */
            QTabWidget::pane {{
                border: 1px solid {t['border_light']};
                border-radius: 8px;
                background-color: {t['bg_secondary']};
                padding: 0;
            }}

            QTabBar::tab {{
                background-color: transparent;
                color: {t['text_secondary']};
                padding: 10px 20px;
                border: none;
                font-weight: 500;
                font-size: {fs(12)}px;
            }}

            QTabBar::tab:selected {{
                color: {t['accent_blue']};
                border-bottom: 2px solid {t['accent_blue']};
            }}

            QTabBar::tab:hover {{
                color: {t['text_primary']};
            }}

            /* ===== GROUPBOX ===== */
            QGroupBox {{
                background-color: {t['bg_secondary']};
                border: 1px solid {t['border_light']};
                border-radius: 8px;
                margin-top: 16px;
                padding: 16px;
                font-weight: 600;
                font-size: {fs(13)}px;
                color: {t['text_primary']};
            }}

            QGroupBox::title {{
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 8px;
                color: {t['text_secondary']};
            }}

            /* ===== DETAIL PANEL ===== */
            QWidget#DetailPanel {{
                background-color: {t['bg_secondary']};
                border-left: 1px solid {t['border_light']};
            }}

            /* ===== LABELS ===== */
            QLabel {{
                color: {t['text_primary']};
            }}

            QLabel#SectionTitle {{
                color: {t['text_secondary']};
                font-size: {fs(11)}px;
                text-transform: uppercase;
                font-weight: 600;
                letter-spacing: 1px;
            }}

            QLabel#ValueLarge {{
                color: {t['text_primary']};
                font-size: {fs(28)}px;
                font-weight: 700;
            }}

            QLabel#ValueMedium {{
                color: {t['text_primary']};
                font-size: {fs(18)}px;
                font-weight: 600;
            }}
            """
