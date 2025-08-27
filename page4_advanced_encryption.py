from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QPushButton, QMessageBox, QApplication, QGraphicsDropShadowEffect, QScrollArea
from PyQt6.QtGui import QFont, QColor
from PyQt6.QtCore import QEasingCurve, QPropertyAnimation
from animated_combobox import AnimatedComboBox
from crypto_utils import CryptoUtils

class Page4AdvancedEncryption(QWidget):
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
        self.select_algorithm_label = QLabel(self.get_string("select_algorithm_level4", "Select Algorithm"))
        self.select_algorithm_label.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        self.algorithm = AnimatedComboBox()
        self.algorithm.addItems(["AES", "RSA", "Blowfish", "ChaCha20", "TripleDES"])
        self.algorithm.currentIndexChanged.connect(self.toggle_key_inputs)
        alg_layout.addWidget(self.select_algorithm_label)
        alg_layout.addWidget(self.algorithm)
        scroll_layout.addLayout(alg_layout)

        # Input text
        input_layout = QVBoxLayout()
        self.enter_text_label = QLabel(self.get_string("enter_text_encryption", "Enter text to encrypt"))
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

        # Key inputs
        self.key_inputs_widget = QWidget()
        self.key_inputs_layout = QVBoxLayout()
        self.key_inputs_widget.setLayout(self.key_inputs_layout)

        # Symmetric key input with buttons
        self.symmetric_key_widget = QWidget()
        symmetric_layout = QVBoxLayout()
        symmetric_key_layout = QHBoxLayout()
        self.symmetric_key_label = QLabel(self.get_string("symmetric_key_label", "Symmetric Key"))
        self.symmetric_key_entry = QTextEdit()
        self.symmetric_key_entry.setFixedHeight(80)
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(10)
        shadow.setColor(QColor(0, 0, 0, 50))
        self.symmetric_key_entry.setGraphicsEffect(shadow)
        self.symmetric_generate_key_button = QPushButton(self.get_string("generate_key_button", "Generate Key"))
        self.add_button_animation(self.symmetric_generate_key_button)
        self.symmetric_generate_key_button.clicked.connect(self.generate_symmetric_key)
        self.symmetric_copy_key_button = QPushButton(self.get_string("copy_key_button", "Copy Key"))
        self.add_button_animation(self.symmetric_copy_key_button)
        self.symmetric_copy_key_button.clicked.connect(self.copy_symmetric_key)
        self.symmetric_paste_key_button = QPushButton(self.get_string("paste_button", "Paste"))
        self.add_button_animation(self.symmetric_paste_key_button)
        self.symmetric_paste_key_button.clicked.connect(self.paste_symmetric_key)
        symmetric_key_layout.addWidget(self.symmetric_key_entry)
        symmetric_key_layout.addWidget(self.symmetric_generate_key_button)
        symmetric_key_layout.addWidget(self.symmetric_copy_key_button)
        symmetric_key_layout.addWidget(self.symmetric_paste_key_button)
        symmetric_layout.addWidget(self.symmetric_key_label)
        symmetric_layout.addLayout(symmetric_key_layout)
        self.symmetric_key_widget.setLayout(symmetric_layout)

        # RSA key inputs with buttons
        self.rsa_keys_widget = QWidget()
        rsa_layout = QVBoxLayout()
        self.rsa_public_key_label = QLabel(self.get_string("rsa_public_key_label", "RSA Public Key"))
        rsa_public_layout = QHBoxLayout()
        self.rsa_public_key_entry = QTextEdit()
        self.rsa_public_key_entry.setFixedHeight(80)
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(10)
        shadow.setColor(QColor(0, 0, 0, 50))
        self.rsa_public_key_entry.setGraphicsEffect(shadow)
        self.rsa_generate_key_button = QPushButton(self.get_string("generate_key_button", "Generate Key"))
        self.add_button_animation(self.rsa_generate_key_button)
        self.rsa_generate_key_button.clicked.connect(self.generate_rsa_key)
        self.rsa_public_copy_key_button = QPushButton(self.get_string("copy_key_button", "Copy Key"))
        self.add_button_animation(self.rsa_public_copy_key_button)
        self.rsa_public_copy_key_button.clicked.connect(self.copy_rsa_public_key)
        self.rsa_public_paste_key_button = QPushButton(self.get_string("paste_button", "Paste"))
        self.add_button_animation(self.rsa_public_paste_key_button)
        self.rsa_public_paste_key_button.clicked.connect(self.paste_rsa_public_key)
        rsa_public_layout.addWidget(self.rsa_public_key_entry)
        rsa_public_layout.addWidget(self.rsa_generate_key_button)
        rsa_public_layout.addWidget(self.rsa_public_copy_key_button)
        rsa_public_layout.addWidget(self.rsa_public_paste_key_button)

        self.rsa_private_key_label = QLabel(self.get_string("rsa_private_key_label", "RSA Private Key"))
        rsa_private_layout = QHBoxLayout()
        self.rsa_private_key_entry = QTextEdit()
        self.rsa_private_key_entry.setFixedHeight(80)
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(10)
        shadow.setColor(QColor(0, 0, 0, 50))
        self.rsa_private_key_entry.setGraphicsEffect(shadow)
        self.rsa_private_copy_key_button = QPushButton(self.get_string("copy_key_button", "Copy Key"))
        self.add_button_animation(self.rsa_private_copy_key_button)
        self.rsa_private_copy_key_button.clicked.connect(self.copy_rsa_private_key)
        self.rsa_private_paste_key_button = QPushButton(self.get_string("paste_button", "Paste"))
        self.add_button_animation(self.rsa_private_paste_key_button)
        self.rsa_private_paste_key_button.clicked.connect(self.paste_rsa_private_key)
        rsa_private_layout.addWidget(self.rsa_private_key_entry)
        rsa_private_layout.addWidget(self.rsa_private_copy_key_button)
        rsa_private_layout.addWidget(self.rsa_private_paste_key_button)

        rsa_layout.addWidget(self.rsa_public_key_label)
        rsa_layout.addLayout(rsa_public_layout)
        rsa_layout.addWidget(self.rsa_private_key_label)
        rsa_layout.addLayout(rsa_private_layout)
        self.rsa_keys_widget.setLayout(rsa_layout)

        self.key_inputs_layout.addWidget(self.symmetric_key_widget)
        self.key_inputs_layout.addWidget(self.rsa_keys_widget)
        scroll_layout.addWidget(self.key_inputs_widget)

        # Buttons
        button_layout = QHBoxLayout()
        self.encrypt_button = QPushButton(self.get_string("encrypt_button_level4", "Encrypt"))
        self.add_button_animation(self.encrypt_button)
        self.encrypt_button.clicked.connect(self.encrypt)
        self.decrypt_button = QPushButton(self.get_string("decrypt_button_level4", "Decrypt"))
        self.add_button_animation(self.decrypt_button)
        self.decrypt_button.clicked.connect(self.decrypt)
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
        button_layout.addWidget(self.encrypt_button)
        button_layout.addWidget(self.decrypt_button)
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

        self.toggle_key_inputs()

    def get_string(self, key, default):
        """Helper method to safely retrieve strings with a fallback."""
        return self.strings.get(self.current_language, {}).get(key, default)

    def add_button_animation(self, button):
        button.setProperty("opacity", 1.0)
        animation = QPropertyAnimation(button, b"windowOpacity")
        animation.setDuration(200)
        animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        button.enterEvent = lambda event: self.start_fade_in(button)
        button.leaveEvent = lambda event: self.start_fade_out(button)

    def start_fade_in(self, button):
        animation = QPropertyAnimation(button, b"windowOpacity")
        animation.setDuration(200)
        animation.setStartValue(button.property("opacity"))
        animation.setEndValue(0.8)
        animation.start()

    def start_fade_out(self, button):
        animation = QPropertyAnimation(button, b"windowOpacity")
        animation.setDuration(200)
        animation.setStartValue(button.property("opacity"))
        animation.setEndValue(1.0)
        animation.start()

    def toggle_key_inputs(self):
        algorithm = self.algorithm.currentText()
        if algorithm == "RSA":
            self.symmetric_key_widget.setVisible(False)
            self.rsa_keys_widget.setVisible(True)
        else:
            self.symmetric_key_widget.setVisible(True)
            self.rsa_keys_widget.setVisible(False)

    def generate_symmetric_key(self):
        try:
            algorithm = self.algorithm.currentText()
            key_size = 256  # Default key size
            if algorithm == "AES":
                key_size = 256  # AES typically uses 256 bits
            elif algorithm == "Blowfish":
                key_size = 128  # Blowfish supports 32-448 bits, using 128 as default
            elif algorithm == "ChaCha20":
                key_size = 256  # ChaCha20 requires 256 bits
            elif algorithm == "TripleDES":
                key_size = 192  # TripleDES typically uses 192 bits
            key = self.crypto_utils.generate_key(key_size)
            self.symmetric_key_entry.setPlainText(key)
        except ValueError as e:
            QMessageBox.critical(self, self.get_string("key_generation_error_title", "Key Generation Error"), self.crypto_utils.get_error_message(str(e)))

    def generate_rsa_key(self):
        try:
            key_size = 2048  # Default RSA key size
            private_key, public_key = self.crypto_utils.generate_rsa_key_pair(key_size)
            self.rsa_public_key_entry.setPlainText(public_key)
            self.rsa_private_key_entry.setPlainText(private_key)
        except ValueError as e:
            QMessageBox.critical(self, self.get_string("key_generation_error_title", "Key Generation Error"), self.crypto_utils.get_error_message(str(e)))

    def copy_symmetric_key(self):
        text = self.symmetric_key_entry.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            QMessageBox.information(self, "Clipboard", self.get_string("key_copied_clipboard", "Key copied to clipboard"))
        else:
            QMessageBox.warning(self, "Clipboard", self.get_string("clipboard_empty", "Clipboard is empty"))

    def paste_symmetric_key(self):
        text = QApplication.clipboard().text()
        if text:
            self.symmetric_key_entry.setPlainText(text)
        else:
            QMessageBox.warning(self, "Clipboard", self.get_string("clipboard_empty", "Clipboard is empty"))

    def copy_rsa_public_key(self):
        text = self.rsa_public_key_entry.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            QMessageBox.information(self, "Clipboard", self.get_string("key_copied_clipboard", "Key copied to clipboard"))
        else:
            QMessageBox.warning(self, "Clipboard", self.get_string("clipboard_empty", "Clipboard is empty"))

    def paste_rsa_public_key(self):
        text = QApplication.clipboard().text()
        if text:
            self.rsa_public_key_entry.setPlainText(text)
        else:
            QMessageBox.warning(self, "Clipboard", self.get_string("clipboard_empty", "Clipboard is empty"))

    def copy_rsa_private_key(self):
        text = self.rsa_private_key_entry.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            QMessageBox.information(self, "Clipboard", self.get_string("key_copied_clipboard", "Key copied to clipboard"))
        else:
            QMessageBox.warning(self, "Clipboard", self.get_string("clipboard_empty", "Clipboard is empty"))

    def paste_rsa_private_key(self):
        text = QApplication.clipboard().text()
        if text:
            self.rsa_private_key_entry.setPlainText(text)
        else:
            QMessageBox.warning(self, "Clipboard", self.get_string("clipboard_empty", "Clipboard is empty"))

    def encrypt(self):
        text = self.input_entry.toPlainText().strip()
        algorithm = self.algorithm.currentText()
        try:
            if not text:
                raise ValueError("invalid_input_empty")
            if algorithm == "AES":
                key = self.symmetric_key_entry.toPlainText().strip()
                if not key:
                    raise ValueError("invalid_aes_key")
                result = self.crypto_utils.aes_encrypt(text, key)
            elif algorithm == "RSA":
                public_key = self.rsa_public_key_entry.toPlainText().strip()
                if not public_key:
                    raise ValueError("invalid_rsa_public_key")
                result = self.crypto_utils.rsa_encrypt(text, public_key)
            elif algorithm == "Blowfish":
                key = self.symmetric_key_entry.toPlainText().strip()
                if not key:
                    raise ValueError("invalid_blowfish_key")
                result = self.crypto_utils.blowfish_encrypt(text, key)
            elif algorithm == "ChaCha20":
                key = self.symmetric_key_entry.toPlainText().strip()
                if not key:
                    raise ValueError("invalid_chacha20_key")
                result = self.crypto_utils.chacha20_encrypt(text, key)
            elif algorithm == "TripleDES":
                key = self.symmetric_key_entry.toPlainText().strip()
                if not key:
                    raise ValueError("invalid_tripledes_key")
                result = self.crypto_utils.tripledes_encrypt(text, key)
            self.result_text.setPlainText(result)
        except ValueError as e:
            QMessageBox.critical(self, self.get_string("algorithm_error_title", "Algorithm Error"), self.crypto_utils.get_error_message(str(e)))

    def decrypt(self):
        text = self.input_entry.toPlainText().strip()
        algorithm = self.algorithm.currentText()
        try:
            if not text:
                raise ValueError("invalid_input_empty")
            if algorithm == "AES":
                key = self.symmetric_key_entry.toPlainText().strip()
                if not key:
                    raise ValueError("invalid_aes_key")
                result = self.crypto_utils.aes_decrypt(text, key)
            elif algorithm == "RSA":
                private_key = self.rsa_private_key_entry.toPlainText().strip()
                if not private_key:
                    raise ValueError("invalid_rsa_private_key")
                result = self.crypto_utils.rsa_decrypt(text, private_key)
            elif algorithm == "Blowfish":
                key = self.symmetric_key_entry.toPlainText().strip()
                if not key:
                    raise ValueError("invalid_blowfish_key")
                result = self.crypto_utils.blowfish_decrypt(text, key)
            elif algorithm == "ChaCha20":
                key = self.symmetric_key_entry.toPlainText().strip()
                if not key:
                    raise ValueError("invalid_chacha20_key")
                result = self.crypto_utils.chacha20_decrypt(text, key)
            elif algorithm == "TripleDES":
                key = self.symmetric_key_entry.toPlainText().strip()
                if not key:
                    raise ValueError("invalid_tripledes_key")
                result = self.crypto_utils.tripledes_decrypt(text, key)
            self.result_text.setPlainText(result)
        except ValueError as e:
            QMessageBox.critical(self, self.get_string("algorithm_error_title", "Algorithm Error"), self.crypto_utils.get_error_message(str(e)))

    def clear_text(self):
        self.input_entry.clear()
        self.result_text.clear()
        self.symmetric_key_entry.clear()
        self.rsa_public_key_entry.clear()
        self.rsa_private_key_entry.clear()

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
        self.select_algorithm_label.setText(self.get_string("select_algorithm_level4", "Select Algorithm"))
        self.enter_text_label.setText(self.get_string("enter_text_encryption", "Enter text to encrypt"))
        self.symmetric_key_label.setText(self.get_string("symmetric_key_label", "Symmetric Key"))
        self.rsa_public_key_label.setText(self.get_string("rsa_public_key_label", "RSA Public Key"))
        self.rsa_private_key_label.setText(self.get_string("rsa_private_key_label", "RSA Private Key"))
        self.encrypt_button.setText(self.get_string("encrypt_button_level4", "Encrypt"))
        self.decrypt_button.setText(self.get_string("decrypt_button_level4", "Decrypt"))
        self.clear_button.setText(self.get_string("clear_button", "Clear"))
        self.copy_input_button.setText(self.get_string("copy_input_button", "Copy Input"))
        self.paste_button.setText(self.get_string("paste_button", "Paste"))
        self.copy_output_button.setText(self.get_string("copy_output_button", "Copy Output"))
        self.result_label.setText(self.get_string("result_label", "Result"))
        self.symmetric_generate_key_button.setText(self.get_string("generate_key_button", "Generate Key"))
        self.symmetric_copy_key_button.setText(self.get_string("copy_key_button", "Copy Key"))
        self.symmetric_paste_key_button.setText(self.get_string("paste_button", "Paste"))
        self.rsa_generate_key_button.setText(self.get_string("generate_key_button", "Generate Key"))
        self.rsa_public_copy_key_button.setText(self.get_string("copy_key_button", "Copy Key"))
        self.rsa_public_paste_key_button.setText(self.get_string("paste_button", "Paste"))
        self.rsa_private_copy_key_button.setText(self.get_string("copy_key_button", "Copy Key"))
        self.rsa_private_paste_key_button.setText(self.get_string("paste_button", "Paste"))