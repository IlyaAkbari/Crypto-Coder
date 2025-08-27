from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QPushButton, QMessageBox, QApplication, QGraphicsDropShadowEffect, QScrollArea, QListWidget
from PyQt6.QtGui import QFont, QColor
from PyQt6.QtCore import QEasingCurve, QPropertyAnimation
from animated_combobox import AnimatedComboBox
from crypto_utils import CryptoUtils

class Page6AlgorithmMixer(QWidget):
    def __init__(self, parent=None, language="English", strings=None):
        super().__init__(parent)
        self.current_language = language
        self.strings = strings or {}
        self.crypto_utils = CryptoUtils(language=self.current_language, strings=self.strings)
        self.parent_app = parent
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout()
        self.setLayout(main_layout)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        scroll_area.setWidget(scroll_widget)
        main_layout.addWidget(scroll_area)

        # Algorithm selection
        alg_layout = QHBoxLayout()
        self.select_algorithm_label = QLabel(self.get_string("select_algorithm_level6", "Select Algorithms to Mix"))
        self.select_algorithm_label.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        self.algo_combobox = AnimatedComboBox()
        # تعریف لیست الگوریتم‌ها
        self.algorithms = [
            ("Caesar", self.crypto_utils.caesar_cipher_encrypt, self.crypto_utils.caesar_cipher_decrypt, "shift"),
            ("Vigenere", self.crypto_utils.vigenere_cipher_encrypt, self.crypto_utils.vigenere_cipher_decrypt, "key"),
            ("Affine", self.crypto_utils.affine_cipher_encrypt, self.crypto_utils.affine_cipher_decrypt, "ab_keys"),
            ("Base64", self.crypto_utils.base64_encode_text, self.crypto_utils.base64_decode_text, None),
            ("ROT13", self.crypto_utils.rot13_encode_text, self.crypto_utils.rot13_decode_text, None),
            ("AES", self.crypto_utils.aes_encrypt, self.crypto_utils.aes_decrypt, "symmetric"),
            ("MD5", self.crypto_utils.md5_hash_text, None, None),  # هش‌ها فقط برای رمزگذاری
        ]
        self.algo_combobox.addItems([algo[0] for algo in self.algorithms])
        alg_layout.addWidget(self.select_algorithm_label)
        alg_layout.addWidget(self.algo_combobox)
        scroll_layout.addLayout(alg_layout)

        # Selected algorithms list
        selected_alg_layout = QVBoxLayout()
        self.selected_algorithms_label = QLabel(self.get_string("selected_algorithms", "Selected Algorithms"))
        self.selected_algorithms_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        self.selected_algorithms_list = QListWidget()
        self.selected_algorithms_list.setFixedHeight(100)
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(10)
        shadow.setColor(QColor(0, 0, 0, 50))
        self.selected_algorithms_list.setGraphicsEffect(shadow)
        selected_alg_layout.addWidget(self.selected_algorithms_label)
        selected_alg_layout.addWidget(self.selected_algorithms_list)
        scroll_layout.addLayout(selected_alg_layout)

        # Add/Remove algorithm buttons
        alg_buttons_layout = QHBoxLayout()
        self.add_algorithm_button = QPushButton("Add Algorithm")
        self.add_button_animation(self.add_algorithm_button)
        self.add_algorithm_button.clicked.connect(self.add_algorithm)
        self.remove_algorithm_button = QPushButton("Remove Selected")
        self.add_button_animation(self.remove_algorithm_button)
        self.remove_algorithm_button.clicked.connect(self.remove_algorithm)
        alg_buttons_layout.addWidget(self.add_algorithm_button)
        alg_buttons_layout.addWidget(self.remove_algorithm_button)
        scroll_layout.addLayout(alg_buttons_layout)

        # Input text
        input_layout = QVBoxLayout()
        self.enter_text_label = QLabel(self.get_string("enter_text_mixer", "Enter text to Mix"))
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

        # Key inputs (for algorithms requiring keys)
        self.key_inputs_widget = QWidget()
        self.key_inputs_layout = QVBoxLayout()
        self.key_inputs_widget.setLayout(self.key_inputs_layout)

        self.key_label = QLabel("Key/Shift (if required)")
        self.key_entry = QTextEdit()
        self.key_entry.setFixedHeight(80)
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(10)
        shadow.setColor(QColor(0, 0, 0, 50))
        self.key_entry.setGraphicsEffect(shadow)
        self.key_inputs_layout.addWidget(self.key_label)
        self.key_inputs_layout.addWidget(self.key_entry)
        scroll_layout.addWidget(self.key_inputs_widget)

        # Action buttons
        button_layout = QHBoxLayout()
        self.mix_button = QPushButton(self.get_string("mix_button_level6", "Mix Algorithms"))
        self.add_button_animation(self.mix_button)
        self.mix_button.clicked.connect(self.mix_algorithms)
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
        button_layout.addWidget(self.mix_button)
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
        self.result_text.setFixedHeight(200)
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(10)
        shadow.setColor(QColor(0, 0, 0, 50))
        self.result_text.setGraphicsEffect(shadow)
        result_layout.addWidget(self.result_label)
        result_layout.addWidget(self.result_text)
        scroll_layout.addLayout(result_layout)

        scroll_layout.addStretch()

    def get_string(self, key, default):
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

    def add_algorithm(self):
        algorithm = self.algo_combobox.currentText()
        if algorithm:
            self.selected_algorithms_list.addItem(algorithm)

    def remove_algorithm(self):
        selected_items = self.selected_algorithms_list.selectedItems()
        for item in selected_items:
            self.selected_algorithms_list.takeItem(self.selected_algorithms_list.row(item))

    def mix_algorithms(self):
        text = self.input_entry.toPlainText().strip()
        if not text:
            QMessageBox.warning(self, self.get_string("algorithm_error_title", "Algorithm Error"), self.get_string("clipboard_empty", "Input is empty"))
            return

        selected_algorithms = [self.selected_algorithms_list.item(i).text() for i in range(self.selected_algorithms_list.count())]
        if not selected_algorithms:
            QMessageBox.warning(self, self.get_string("algorithm_error_title", "Algorithm Error"), "No algorithms selected")
            return

        key_input = self.key_entry.toPlainText().strip()
        result = text

        for algo_name in selected_algorithms:
            algo_data = next((algo for algo in self.algorithms if algo[0] == algo_name), None)
            if not algo_data:
                continue
            algo, encrypt_func, decrypt_func, key_type = algo_data
            try:
                if key_type == "shift":
                    try:
                        shift = int(key_input) if key_input else 3  # Default shift
                        result = encrypt_func(result, shift)
                    except ValueError:
                        raise ValueError("caesar_shift_error")
                elif key_type == "key":
                    if not key_input:
                        raise ValueError(f"{algo.lower()}_key_empty_error")
                    result = encrypt_func(result, key_input)
                elif key_type == "ab_keys":
                    if not key_input:
                        raise ValueError("affine_key_error")
                    a, b = map(int, key_input.split(',')) if ',' in key_input else (5, 8)  # Default a, b
                    result = encrypt_func(result, a, b)
                elif key_type == "symmetric":
                    if not key_input:
                        raise ValueError(f"{algo.lower()}_key")
                    result = encrypt_func(result, key_input)
                elif key_type is None and encrypt_func:
                    result = encrypt_func(result)
            except ValueError as e:
                QMessageBox.critical(self, self.get_string("algorithm_error_title", "Algorithm Error"), self.crypto_utils.get_error_message(str(e)))
                return

        self.result_text.setPlainText(result)

    def clear_text(self):
        self.input_entry.clear()
        self.result_text.clear()
        self.key_entry.clear()
        self.selected_algorithms_list.clear()

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
        self.select_algorithm_label.setText(self.get_string("select_algorithm_level6", "Select Algorithms to Mix"))
        self.selected_algorithms_label.setText(self.get_string("selected_algorithms", "Selected Algorithms"))
        self.mix_button.setText(self.get_string("mix_button_level6", "Mix Algorithms"))
        self.clear_button.setText(self.get_string("clear_button", "Clear"))
        self.copy_input_button.setText(self.get_string("copy_input_button", "Copy Input"))
        self.paste_button.setText(self.get_string("paste_button", "Paste"))
        self.copy_output_button.setText(self.get_string("copy_output_button", "Copy Output"))
        self.result_label.setText(self.get_string("result_label", "Result"))
        self.key_label.setText("Key/Shift (if required)")