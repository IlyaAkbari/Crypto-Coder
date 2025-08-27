from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QPushButton, QMessageBox, QApplication, QGraphicsDropShadowEffect, QScrollArea
from PyQt6.QtGui import QFont, QColor
from animated_combobox import AnimatedComboBox
from crypto_utils import CryptoUtils

class Page3Hashers(QWidget):
    def __init__(self, parent=None, language="English", strings=None):
        super().__init__(parent)
        self.current_language = language
        self.strings = strings or {}
        self.crypto_utils = CryptoUtils(language=self.current_language, strings=self.strings)
        self.init_ui()
        self.parent_app = parent

    def init_ui(self):
        # Main layout
        main_layout = QVBoxLayout()
        self.setLayout(main_layout)

        # Scroll area
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        scroll_area.setWidget(scroll_widget)
        main_layout.addWidget(scroll_area)

        # Algorithm selection
        alg_layout = QHBoxLayout()
        self.select_algorithm_label = QLabel(self.get_string("select_algorithm_level3", "Select Algorithm"))
        self.select_algorithm_label.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        self.algorithm = AnimatedComboBox()
        self.algorithm.addItems(["MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SHA3_256", "SHA3_512", "Whirlpool", "Blake2b", "Blake2s"])
        alg_layout.addWidget(self.select_algorithm_label)
        alg_layout.addWidget(self.algorithm)
        scroll_layout.addLayout(alg_layout)

        # Input text
        input_layout = QVBoxLayout()
        self.enter_text_label = QLabel(self.get_string("enter_text_hashing", "Enter text to hash"))
        self.enter_text_label.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        self.input_entry = QTextEdit()
        self.input_entry.setFixedHeight(100)
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(10)
        shadow.setColor(QColor(0, 0, 0, 50))
        self.input_entry.setGraphicsEffect(shadow)
        input_layout.addWidget(self.enter_text_label)
        input_layout.addWidget(self.input_entry)
        scroll_layout.addLayout(input_layout)

        # Buttons
        button_layout = QHBoxLayout()
        self.hash_button = QPushButton(self.get_string("hash_button", "Hash"))
        self.add_button_animation(self.hash_button)
        self.hash_button.clicked.connect(self.hash)
        self.clear_button = QPushButton(self.get_string("clear_button", "Clear"))
        self.add_button_animation(self.clear_button)
        self.clear_button.clicked.connect(self.clear_text)
        self.copy_input_button = QPushButton(self.get_string("copy_input_button", "Copy Input"))
        self.add_button_animation(self.copy_input_button)
        self.copy_input_button.clicked.connect(self.copy_to_clipboard_input)
        self.paste_button = QPushButton(self.get_string("paste_button", "Paste"))
        self.add_button_animation(self.paste_button)
        self.paste_button.clicked.connect(self.paste_text)
        self.copy_output_button = QPushButton(self.get_string("copy_output_button", "Copy Output"))
        self.add_button_animation(self.copy_output_button)
        self.copy_output_button.clicked.connect(self.copy_to_clipboard)
        button_layout.addWidget(self.hash_button)
        button_layout.addWidget(self.clear_button)
        button_layout.addWidget(self.copy_input_button)
        button_layout.addWidget(self.paste_button)
        button_layout.addWidget(self.copy_output_button)
        scroll_layout.addLayout(button_layout)

        # Result
        result_layout = QVBoxLayout()
        self.result_label = QLabel(self.get_string("result_label", "Result"))
        self.result_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        self.result_text = QTextEdit()
        self.result_text.setFixedHeight(100)
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(10)
        shadow.setColor(QColor(0, 0, 0, 50))
        self.result_text.setGraphicsEffect(shadow)
        result_layout.addWidget(self.result_label)
        result_layout.addWidget(self.result_text)
        scroll_layout.addLayout(result_layout)

        scroll_layout.addStretch()

    def get_string(self, key, default):
        """Helper method to safely retrieve strings with a fallback."""
        return self.strings.get(self.current_language, {}).get(key, default)

    def add_button_animation(self, button):
        from PyQt6.QtCore import QPropertyAnimation, QEasingCurve
        button.setProperty("opacity", 1.0)
        animation = QPropertyAnimation(button, b"windowOpacity")
        animation.setDuration(200)
        animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        button.enterEvent = lambda event: self.start_fade_in(button)
        button.leaveEvent = lambda event: self.start_fade_out(button)

    def start_fade_in(self, button):
        from PyQt6.QtCore import QPropertyAnimation, QEasingCurve
        animation = QPropertyAnimation(button, b"windowOpacity")
        animation.setDuration(200)
        animation.setStartValue(button.property("opacity"))
        animation.setEndValue(0.8)
        animation.start()

    def start_fade_out(self, button):
        from PyQt6.QtCore import QPropertyAnimation, QEasingCurve
        animation = QPropertyAnimation(button, b"windowOpacity")
        animation.setDuration(200)
        animation.setStartValue(button.property("opacity"))
        animation.setEndValue(1.0)
        animation.start()

    def hash(self):
        text = self.input_entry.toPlainText().strip()
        algorithm = self.algorithm.currentText()
        try:
            if not text:
                raise ValueError("invalid_input_empty")
            if algorithm == "MD5":
                result = self.crypto_utils.md5_hash_text(text)
            elif algorithm == "SHA1":
                result = self.crypto_utils.sha1_hash_text(text)
            elif algorithm == "SHA224":
                result = self.crypto_utils.sha224_hash_text(text)
            elif algorithm == "SHA256":
                result = self.crypto_utils.sha256_hash_text(text)
            elif algorithm == "SHA384":
                result = self.crypto_utils.sha384_hash_text(text)
            elif algorithm == "SHA512":
                result = self.crypto_utils.sha512_hash_text(text)
            elif algorithm == "SHA3_256":
                result = self.crypto_utils.sha3_256_hash_text(text)
            elif algorithm == "SHA3_512":
                result = self.crypto_utils.sha3_512_hash_text(text)
            elif algorithm == "Whirlpool":
                result = self.crypto_utils.whirlpool_hash_text(text)
            elif algorithm == "Blake2b":
                result = self.crypto_utils.blake2b_hash_text(text)
            elif algorithm == "Blake2s":
                result = self.crypto_utils.blake2s_hash_text(text)
            else:
                raise ValueError("invalid_algorithm")
            self.result_text.setPlainText(result)
        except ValueError as e:
            QMessageBox.critical(self, self.get_string("algorithm_error_title", "Algorithm Error"), self.crypto_utils.get_error_message(str(e)))
        except Exception as e:
            QMessageBox.critical(self, self.get_string("algorithm_error_title", "Algorithm Error"), self.crypto_utils.get_error_message(f"unexpected_error: {str(e)}"))

    def clear_text(self):
        self.input_entry.clear()
        self.result_text.clear()

    def copy_to_clipboard(self):
        text = self.result_text.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            QMessageBox.information(self, "Clipboard", self.get_string("clipboard_output_copied", "Output copied to clipboard"))
        else:
            QMessageBox.warning(self, "Clipboard", self.get_string("clipboard_empty", "Clipboard is empty"))

    def copy_to_clipboard_input(self):
        text = self.input_entry.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            QMessageBox.information(self, "Clipboard", self.get_string("clipboard_input_copied", "Input copied to clipboard"))
        else:
            QMessageBox.warning(self, "Clipboard", self.get_string("clipboard_empty", "Clipboard is empty"))

    def paste_text(self):
        text = QApplication.clipboard().text()
        if text:
            self.input_entry.setPlainText(text)
        else:
            QMessageBox.warning(self, "Clipboard", self.get_string("clipboard_empty", "Clipboard is empty"))

    def update_language(self, language):
        self.current_language = language
        self.crypto_utils.language = language
        self.select_algorithm_label.setText(self.get_string("select_algorithm_level3", "Select Algorithm"))
        self.enter_text_label.setText(self.get_string("enter_text_hashing", "Enter text to hash"))
        self.hash_button.setText(self.get_string("hash_button", "Hash"))
        self.clear_button.setText(self.get_string("clear_button", "Clear"))
        self.copy_input_button.setText(self.get_string("copy_input_button", "Copy Input"))
        self.paste_button.setText(self.get_string("paste_button", "Paste"))
        self.copy_output_button.setText(self.get_string("copy_output_button", "Copy Output"))
        self.result_label.setText(self.get_string("result_label", "Result"))