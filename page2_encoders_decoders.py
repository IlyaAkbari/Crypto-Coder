from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QMessageBox
from PyQt6.QtGui import QFont
from animated_combobox import AnimatedComboBox
from crypto_utils import CryptoUtils

class Page2EncodersDecoders(QWidget):
    def __init__(self, parent=None, language="English", strings=None):
        super().__init__(parent)
        self.current_language = language
        self.strings = strings
        self.init_ui()
        self.parent_app = parent

    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        self.enter_text_label = QLabel(self.strings[self.current_language]["enter_text_encode_decode"])
        layout.addWidget(self.enter_text_label)
        self.input_entry = QLineEdit()
        layout.addWidget(self.input_entry)

        button_layout = QHBoxLayout()
        self.clear_button = QPushButton(self.strings[self.current_language]["clear_button"])
        self.clear_button.clicked.connect(self.clear_text)
        self.copy_input_button = QPushButton(self.strings[self.current_language]["copy_input_button"])
        self.copy_input_button.clicked.connect(self.copy_to_clipboard_input)
        self.paste_button = QPushButton(self.strings[self.current_language]["paste_button"])
        self.paste_button.clicked.connect(self.paste_text)
        self.copy_output_button = QPushButton(self.strings[self.current_language]["copy_output_button"])
        self.copy_output_button.clicked.connect(self.copy_to_clipboard)
        button_layout.addWidget(self.clear_button)
        button_layout.addWidget(self.copy_input_button)
        button_layout.addWidget(self.paste_button)
        button_layout.addWidget(self.copy_output_button)
        layout.addLayout(button_layout)

        alg_layout = QHBoxLayout()
        self.select_algorithm_label = QLabel(self.strings[self.current_language]["select_algorithm_level2"])
        self.algorithm = AnimatedComboBox()
        self.algorithm.addItems([
            "Base64", "ROT13", "URL Encoding", "Hex Encoding",
            "ASCII Encoding", "Binary Encoding", "Morse Code",
            "Quoted-Printable", "Unicode Escape", "Base32", "UUEncode"
        ])
        alg_layout.addWidget(self.select_algorithm_label)
        alg_layout.addWidget(self.algorithm)
        layout.addLayout(alg_layout)

        action_layout = QHBoxLayout()
        self.encode_button = QPushButton(self.strings[self.current_language]["encode_button_level2"])
        self.encode_button.clicked.connect(self.encode)
        self.decode_button = QPushButton(self.strings[self.current_language]["decode_button_level2"])
        self.decode_button.clicked.connect(self.decode)
        action_layout.addWidget(self.encode_button)
        action_layout.addWidget(self.decode_button)
        layout.addLayout(action_layout)

        self.result_label = QLabel(self.strings[self.current_language]["result_label"])
        self.result_text = QTextEdit()
        self.result_text.setFixedHeight(120)
        layout.addWidget(self.result_label)
        layout.addWidget(self.result_text)
        layout.addStretch()

    def encode(self):
        text = self.input_entry.text()
        algorithm = self.algorithm.currentText()
        try:
            if algorithm == "Base64":
                result = CryptoUtils.base64_encode_text(text)
            elif algorithm == "ROT13":
                result = CryptoUtils.rot13_encode_text(text)
            elif algorithm == "URL Encoding":
                result = CryptoUtils.url_encode_text(text)
            elif algorithm == "Hex Encoding":
                result = CryptoUtils.hex_encode_text(text)
            elif algorithm == "ASCII Encoding":
                result = CryptoUtils.ascii_encode_text(text)
            elif algorithm == "Binary Encoding":
                result = CryptoUtils.binary_encode_text(text)
            elif algorithm == "Morse Code":
                result = CryptoUtils.morse_encode_text(text)
            elif algorithm == "Quoted-Printable":
                result = CryptoUtils.quoted_printable_encode_text(text)
            elif algorithm == "Unicode Escape":
                result = CryptoUtils.unicode_escape_encode_text(text)
            elif algorithm == "Base32":
                result = CryptoUtils.base32_encode_text(text)
            elif algorithm == "UUEncode":
                result = CryptoUtils.uuencode_text(text)
            self.result_text.setText(result)
        except ValueError as e:
            QMessageBox.critical(self, self.strings[self.current_language]["algorithm_error_title"], str(e))

    def decode(self):
        text = self.input_entry.text()
        algorithm = self.algorithm.currentText()
        try:
            if algorithm == "Base64":
                result = CryptoUtils.base64_decode_text(text)
            elif algorithm == "ROT13":
                result = CryptoUtils.rot13_decode_text(text)
            elif algorithm == "URL Encoding":
                result = CryptoUtils.url_decode_text(text)
            elif algorithm == "Hex Encoding":
                result = CryptoUtils.hex_decode_text(text)
            elif algorithm == "ASCII Encoding":
                result = CryptoUtils.ascii_decode_text(text)
            elif algorithm == "Binary Encoding":
                result = CryptoUtils.binary_decode_text(text)
            elif algorithm == "Morse Code":
                result = CryptoUtils.morse_decode_text(text)
            elif algorithm == "Quoted-Printable":
                result = CryptoUtils.quoted_printable_decode_text(text)
            elif algorithm == "Unicode Escape":
                result = CryptoUtils.unicode_escape_decode_text(text)
            elif algorithm == "Base32":
                result = CryptoUtils.base32_decode_text(text)
            elif algorithm == "UUEncode":
                result = CryptoUtils.uudecode_text(text)
            self.result_text.setText(result)
        except ValueError as e:
            QMessageBox.critical(self, self.strings[self.current_language]["algorithm_error_title"], str(e))

    def clear_text(self):
        self.input_entry.clear()
        self.result_text.clear()

    def copy_to_clipboard(self):
        text = self.result_text.toPlainText()
        if text:
            self.parent_app.clipboard.setText(text)
            QMessageBox.information(self, "Clipboard", self.strings[self.current_language]["clipboard_output_copied"])
        else:
            QMessageBox.warning(self, "Clipboard", self.strings[self.current_language]["clipboard_empty"])

    def copy_to_clipboard_input(self):
        text = self.input_entry.text()
        if text:
            self.parent_app.clipboard.setText(text)
            QMessageBox.information(self, "Clipboard", self.strings[self.current_language]["clipboard_input_copied"])
        else:
            QMessageBox.warning(self, "Clipboard", self.strings[self.current_language]["clipboard_empty"])

    def paste_text(self):
        text = self.parent_app.clipboard.text()
        if text:
            self.input_entry.setText(text)

    def update_language(self, language):
        self.current_language = language
        self.enter_text_label.setText(self.strings[self.current_language]["enter_text_encode_decode"])
        self.clear_button.setText(self.strings[self.current_language]["clear_button"])
        self.copy_input_button.setText(self.strings[self.current_language]["copy_input_button"])
        self.paste_button.setText(self.strings[self.current_language]["paste_button"])
        self.copy_output_button.setText(self.strings[self.current_language]["copy_output_button"])
        self.select_algorithm_label.setText(self.strings[self.current_language]["select_algorithm_level2"])
        self.encode_button.setText(self.strings[self.current_language]["encode_button_level2"])
        self.decode_button.setText(self.strings[self.current_language]["decode_button_level2"])
        self.result_label.setText(self.strings[self.current_language]["result_label"])