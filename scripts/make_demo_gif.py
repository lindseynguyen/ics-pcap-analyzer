"""Record docs/demo.gif: a walk through the GUI on samples/attack_scenarios.pcap.

    QT_QPA_PLATFORM=offscreen python scripts/make_demo_gif.py

Needs the GUI extras and Pillow: pip install -e ".[gui]" pillow
"""
import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from PIL import Image  # noqa: E402
from PyQt5.QtCore import QBuffer, QIODevice  # noqa: E402
from PyQt5.QtWidgets import QApplication, QMessageBox  # noqa: E402

from ot_pcap_analyzer import AnalyzerConfig, OTAnalyzer, gui  # noqa: E402

SAMPLE = ROOT / "samples" / "attack_scenarios.pcap"
OUT = ROOT / "docs" / "demo.gif"
SIZE = (1440, 900)        # window size the frames are captured at
WIDTH = 960               # width of the published GIF
# (view index, seconds on screen); indexes follow the sidebar order in gui.MainWindow
TOUR = [(0, 3.0), (2, 2.5), (7, 3.0), (4, 2.5), (3, 2.0), (1, 2.0), (6, 2.0)]


def _frame(widget, app):
    for _ in range(20):
        app.processEvents()
    buf = QBuffer()
    buf.open(QIODevice.ReadWrite)
    widget.grab().save(buf, "PNG")
    from io import BytesIO
    img = Image.open(BytesIO(bytes(buf.data()))).convert("RGB")
    h = round(img.height * WIDTH / img.width)
    return img.resize((WIDTH, h), Image.LANCZOS)


def main() -> None:
    app = QApplication.instance() or QApplication(sys.argv)
    QMessageBox.exec_ = lambda self: 0

    analyzer = OTAnalyzer(AnalyzerConfig(enable_correlation=True, enable_storyline=True))
    analyzer.analyze_capture(str(SAMPLE))

    w = gui.MainWindow()
    w.resize(*SIZE)
    w.show()
    w.analyzer = analyzer
    w.worker = None
    w.on_analysis_complete()

    frames, durations = [], []
    for index, seconds in TOUR:
        w._navigate_to_view(index)
        w._refresh_current_view()
        frames.append(_frame(w, app))
        durations.append(int(seconds * 1000))
    # finish on the dashboard in the other theme
    w._navigate_to_view(0)
    w._toggle_theme()
    frames.append(_frame(w, app))
    durations.append(3000)
    w._toggle_theme()
    w.close()

    # one shared palette keeps colours stable between frames and the file small
    palette = frames[0].quantize(colors=128, method=Image.MEDIANCUT)
    quantized = [f.quantize(palette=palette, dither=Image.Dither.NONE) for f in frames]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    quantized[0].save(OUT, save_all=True, append_images=quantized[1:],
                      duration=durations, loop=0, optimize=True)
    print(f"wrote {OUT.relative_to(ROOT)} ({OUT.stat().st_size // 1024} KB, {len(frames)} frames)")


if __name__ == "__main__":
    main()
