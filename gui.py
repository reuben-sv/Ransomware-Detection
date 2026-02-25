import sys
import os
from pathlib import Path
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QFileDialog, QProgressBar,
    QFrame, QScrollArea, QMessageBox, QSizePolicy,
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont

from analysis_modules.static_analysis import analyze_executable_static
from analysis_modules.dynamic_analysis import analyze_executable_dynamic
from report_generator import report_generator


# ---------------- CONFIG ----------------
STATIC_WEIGHT = 0.3
DYNAMIC_WEIGHT = 0.7


# ---------------- SCORE HELPERS ----------------
def static_score_from_probability(prob):
    return int(prob * 100)


def dynamic_score_from_probability(prob):
    return int(prob * 100)


def final_ransomware_score(static_score, dynamic_score=None):
    if dynamic_score is None:
        return static_score
    return int(static_score * STATIC_WEIGHT + dynamic_score * DYNAMIC_WEIGHT)


def verdict_from_score(score):
    if score >= 80:
        return "STRONG RANSOMWARE"
    elif score >= 50:
        return "POSSIBLE / WEAK RANSOMWARE"
    else:
        return "BENIGN"


# ---------------- STYLESHEET ----------------
STYLESHEET = """
QMainWindow {
    background-color: #1a1a2e;
}
QLabel {
    color: #eaeaea;
    font-family: 'Segoe UI', Arial, sans-serif;
}
QLineEdit {
    background-color: #1e1e3a;
    color: #eaeaea;
    border: 1px solid #2a2a4a;
    border-radius: 6px;
    padding: 8px 12px;
    font-size: 13px;
    font-family: 'Segoe UI', Arial, sans-serif;
}
QLineEdit:focus {
    border-color: #e94560;
}
QPushButton {
    background-color: #e94560;
    color: white;
    border: none;
    border-radius: 6px;
    padding: 10px 24px;
    font-size: 14px;
    font-weight: bold;
    font-family: 'Segoe UI', Arial, sans-serif;
}
QPushButton:hover {
    background-color: #ff6b6b;
}
QPushButton:pressed {
    background-color: #c0392b;
}
QPushButton:disabled {
    background-color: #3a3a5a;
    color: #6c6c80;
}
QPushButton#secondary_btn {
    background-color: #0f3460;
    border: 1px solid #e94560;
}
QPushButton#secondary_btn:hover {
    background-color: #1a2a50;
}
QPushButton#secondary_btn:disabled {
    background-color: #2a2a3a;
    border: 1px solid #3a3a5a;
    color: #6c6c80;
}
QProgressBar {
    background-color: #1e1e3a;
    border: 1px solid #2a2a4a;
    border-radius: 8px;
    height: 22px;
    text-align: center;
    color: #eaeaea;
    font-weight: bold;
}
QProgressBar::chunk {
    border-radius: 7px;
    background-color: #e94560;
}
QScrollArea {
    background-color: transparent;
    border: none;
}
QScrollBar:vertical {
    background-color: #1a1a2e;
    width: 8px;
    border-radius: 4px;
}
QScrollBar::handle:vertical {
    background-color: #3a3a5a;
    border-radius: 4px;
    min-height: 30px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
"""


# ---------------- ANALYSIS WORKER ----------------
class AnalysisWorker(QThread):
    progress_update = pyqtSignal(str)
    analysis_complete = pyqtSignal(dict)
    analysis_error = pyqtSignal(str)

    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path

    def run(self):
        try:
            self.progress_update.emit("Running static analysis...")
            static_label, static_conf, static_reasons = analyze_executable_static(
                self.file_path, "models/Static_Model.pkl"
            )
            static_score = static_score_from_probability(static_conf)

            self.progress_update.emit("Running dynamic analysis (monitoring for ~8 seconds)...")
            dynamic_prob = analyze_executable_dynamic(self.file_path)
            dynamic_score = dynamic_score_from_probability(dynamic_prob)

            self.progress_update.emit("Computing final verdict...")
            final_score = final_ransomware_score(static_score, dynamic_score)
            verdict = verdict_from_score(final_score)

            result = {
                "file_path": self.file_path,
                "static_reasons": static_reasons,
                "static_score": static_score,
                "dynamic_score": dynamic_score,
                "final_score": final_score,
                "verdict": verdict,
            }
            self.analysis_complete.emit(result)
        except Exception as e:
            self.analysis_error.emit(f"{type(e).__name__}: {e}")


# ---------------- SCORE BAR WIDGET ----------------
class ScoreBar(QWidget):
    def __init__(self, title):
        super().__init__()
        self._title = title
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        self._label = QLabel(self._title)
        self._label.setFont(QFont("Segoe UI", 10))
        self._label.setStyleSheet("color: #a0a0b0;")
        layout.addWidget(self._label)

        self._bar = QProgressBar()
        self._bar.setRange(0, 100)
        self._bar.setValue(0)
        self._bar.setFixedHeight(24)
        self._bar.setFormat("%v / 100")
        layout.addWidget(self._bar)

    def set_score(self, value):
        self._bar.setValue(value)
        color = self._color_for_score(value)
        self._bar.setStyleSheet(f"""
            QProgressBar::chunk {{
                background-color: {color};
                border-radius: 7px;
            }}
        """)

    def reset(self):
        self._bar.setValue(0)
        self._bar.setStyleSheet("")

    @staticmethod
    def _color_for_score(score):
        if score >= 80:
            return "#e74c3c"
        elif score >= 50:
            return "#f39c12"
        else:
            return "#2ecc71"


# ---------------- MAIN WINDOW ----------------
class RansomwareDetectorGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self._last_result = None
        self._worker = None
        self.setWindowTitle("Ransomware Detection System")
        self.setMinimumSize(900, 700)
        self.resize(1000, 800)
        self._build_ui()
        self._center_window()
        self._check_models()

    def _center_window(self):
        screen = QApplication.primaryScreen().geometry()
        self.move(
            (screen.width() - self.width()) // 2,
            (screen.height() - self.height()) // 2,
        )

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(32, 24, 32, 16)
        main_layout.setSpacing(16)

        # Title
        title = QLabel("Ransomware Detection System")
        title.setFont(QFont("Segoe UI", 24, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title)

        subtitle = QLabel("Hybrid static + dynamic analysis tool")
        subtitle.setFont(QFont("Segoe UI", 12))
        subtitle.setStyleSheet("color: #6c6c80;")
        subtitle.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(subtitle)

        # File Selection
        main_layout.addWidget(self._build_file_section())

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(12)

        self._start_btn = QPushButton("Start Analysis")
        self._start_btn.setCursor(Qt.PointingHandCursor)
        self._start_btn.clicked.connect(self._on_start_analysis)
        btn_layout.addWidget(self._start_btn)

        self._report_btn = QPushButton("Generate Report")
        self._report_btn.setObjectName("secondary_btn")
        self._report_btn.setCursor(Qt.PointingHandCursor)
        self._report_btn.setEnabled(False)
        self._report_btn.clicked.connect(self._on_generate_report)
        btn_layout.addWidget(self._report_btn)

        main_layout.addLayout(btn_layout)

        # Status
        main_layout.addWidget(self._build_status_section())

        # Results
        self._results_section = self._build_results_section()
        self._results_section.setVisible(False)
        main_layout.addWidget(self._results_section)

        main_layout.addStretch()

        # Footer
        footer = QLabel("Ransomware Detection System v1.0")
        footer.setFont(QFont("Segoe UI", 9))
        footer.setStyleSheet("color: #4a4a60;")
        footer.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(footer)

    def _make_card(self):
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background-color: #16213e;
                border: 1px solid #2a2a4a;
                border-radius: 10px;
                padding: 16px;
            }
        """)
        return frame

    def _build_file_section(self):
        card = self._make_card()
        layout = QHBoxLayout(card)
        layout.setSpacing(10)

        label = QLabel("File:")
        label.setFont(QFont("Segoe UI", 13, QFont.Bold))
        layout.addWidget(label)

        self._file_input = QLineEdit()
        self._file_input.setPlaceholderText("Select an executable (.exe) file...")
        self._file_input.setReadOnly(True)
        self._file_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        layout.addWidget(self._file_input)

        browse_btn = QPushButton("Browse")
        browse_btn.setObjectName("secondary_btn")
        browse_btn.setCursor(Qt.PointingHandCursor)
        browse_btn.clicked.connect(self._on_browse)
        layout.addWidget(browse_btn)

        return card

    def _build_status_section(self):
        card = self._make_card()
        layout = QVBoxLayout(card)
        layout.setSpacing(8)

        self._status_label = QLabel("Ready")
        self._status_label.setFont(QFont("Segoe UI", 12))
        layout.addWidget(self._status_label)

        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        self._progress_bar.setFixedHeight(22)
        self._progress_bar.setVisible(False)
        layout.addWidget(self._progress_bar)

        return card

    def _build_results_section(self):
        card = self._make_card()
        layout = QVBoxLayout(card)
        layout.setSpacing(12)

        results_title = QLabel("Results")
        results_title.setFont(QFont("Segoe UI", 16, QFont.Bold))
        layout.addWidget(results_title)

        # Score bars
        scores_layout = QHBoxLayout()
        scores_layout.setSpacing(16)

        self._static_bar = ScoreBar("Static Score")
        self._dynamic_bar = ScoreBar("Dynamic Score")
        self._final_bar = ScoreBar("Final Score")

        scores_layout.addWidget(self._static_bar)
        scores_layout.addWidget(self._dynamic_bar)
        scores_layout.addWidget(self._final_bar)
        layout.addLayout(scores_layout)

        # Verdict
        self._verdict_frame = QFrame()
        self._verdict_frame.setFixedHeight(60)
        verdict_layout = QVBoxLayout(self._verdict_frame)
        verdict_layout.setAlignment(Qt.AlignCenter)

        self._verdict_label = QLabel("")
        self._verdict_label.setFont(QFont("Segoe UI", 20, QFont.Bold))
        self._verdict_label.setAlignment(Qt.AlignCenter)
        verdict_layout.addWidget(self._verdict_label)
        layout.addWidget(self._verdict_frame)

        # Factors
        factors_title = QLabel("Top Contributing Factors")
        factors_title.setFont(QFont("Segoe UI", 13, QFont.Bold))
        factors_title.setStyleSheet("color: #a0a0b0;")
        layout.addWidget(factors_title)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFixedHeight(180)

        self._factors_container = QWidget()
        self._factors_layout = QVBoxLayout(self._factors_container)
        self._factors_layout.setContentsMargins(4, 4, 4, 4)
        self._factors_layout.setSpacing(2)
        self._factors_layout.addStretch()

        scroll.setWidget(self._factors_container)
        layout.addWidget(scroll)

        return card

    # ---------------- ACTIONS ----------------
    def _check_models(self):
        static_exists = Path("models/Static_Model.pkl").is_file()
        if not static_exists:
            QMessageBox.warning(
                self,
                "Models Not Found",
                "The static analysis model is missing.\n\n"
                "Please run Setup (option 0) from main.py first to train the models.\n\n"
                "Expected: models/Static_Model.pkl",
            )

    def _on_browse(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Executable", "",
            "Executables (*.exe);;All Files (*)"
        )
        if path:
            self._file_input.setText(path)

    def _on_start_analysis(self):
        file_path = self._file_input.text().strip()

        if not file_path:
            QMessageBox.warning(self, "No File", "Please select a file first.")
            return

        if not os.path.isfile(file_path):
            QMessageBox.warning(self, "File Not Found", f"File does not exist:\n{file_path}")
            return

        if not file_path.lower().endswith(".exe"):
            QMessageBox.warning(self, "Invalid File", "Please select an .exe file.")
            return

        # Disable controls
        self._start_btn.setEnabled(False)
        self._report_btn.setEnabled(False)
        self._results_section.setVisible(False)
        self._last_result = None

        # Show progress
        self._progress_bar.setRange(0, 0)  # indeterminate
        self._progress_bar.setVisible(True)
        self._status_label.setText("Starting analysis...")

        # Launch worker
        self._worker = AnalysisWorker(file_path)
        self._worker.progress_update.connect(self._on_progress)
        self._worker.analysis_complete.connect(self._on_analysis_complete)
        self._worker.analysis_error.connect(self._on_analysis_error)
        self._worker.start()

    def _on_progress(self, message):
        self._status_label.setText(message)

    def _on_analysis_complete(self, result):
        self._last_result = result

        # Update scores
        self._static_bar.set_score(result["static_score"])
        self._dynamic_bar.set_score(result["dynamic_score"])
        self._final_bar.set_score(result["final_score"])

        # Verdict
        self._set_verdict(result["verdict"])

        # Factors
        self._populate_factors(result["static_reasons"])

        # Show results
        self._results_section.setVisible(True)

        # Reset status
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(100)
        self._status_label.setText("Analysis complete")

        # Re-enable controls
        self._start_btn.setEnabled(True)
        self._report_btn.setEnabled(True)

    def _on_analysis_error(self, error):
        self._progress_bar.setVisible(False)
        self._status_label.setText("Analysis failed")
        self._start_btn.setEnabled(True)
        QMessageBox.critical(self, "Analysis Error", f"An error occurred:\n\n{error}")

    def _set_verdict(self, verdict):
        self._verdict_label.setText(verdict)
        color_map = {
            "BENIGN": ("#2ecc71", "#0a3d1a"),
            "POSSIBLE / WEAK RANSOMWARE": ("#f39c12", "#3d2e0a"),
            "STRONG RANSOMWARE": ("#e74c3c", "#3d0a0a"),
        }
        text_color, bg_color = color_map.get(verdict, ("#eaeaea", "#16213e"))
        self._verdict_frame.setStyleSheet(
            f"background-color: {bg_color}; border-radius: 8px;"
        )
        self._verdict_label.setStyleSheet(
            f"color: {text_color}; font-size: 20px; font-weight: bold;"
        )

    def _populate_factors(self, reasons):
        # Clear previous
        while self._factors_layout.count():
            child = self._factors_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        for reason_str in reasons:
            label = QLabel(reason_str.strip())
            label.setWordWrap(True)
            label.setFont(QFont("Consolas", 10))
            if "Malware" in reason_str:
                label.setStyleSheet("color: #e74c3c; padding: 4px 8px;")
            else:
                label.setStyleSheet("color: #2ecc71; padding: 4px 8px;")
            self._factors_layout.addWidget(label)

        self._factors_layout.addStretch()

    def _on_generate_report(self):
        if self._last_result is None:
            return
        try:
            report_generator(self._last_result)
            self._status_label.setText("Report generated successfully")
        except Exception as e:
            QMessageBox.critical(
                self, "Report Error",
                f"Failed to generate report:\n\n{type(e).__name__}: {e}"
            )

    def closeEvent(self, event):
        if self._worker and self._worker.isRunning():
            self._worker.terminate()
            self._worker.wait()
        event.accept()


# ---------------- ENTRY POINT ----------------
def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(STYLESHEET)
    window = RansomwareDetectorGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
