from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QSpinBox, QTextEdit, QMessageBox
from PyQt6.QtGui import QFont
from animated_combobox import AnimatedComboBox
from crypto_utils import CryptoUtils

class Page1Ciphers(QWidget):
    def __init__(self, parent=None, language="English", strings=None):
        super().__init__(parent)
        self.current_language = language
        self.strings = strings
        self.init_ui()
        self.parent_app = parent

    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        self.enter_text_label = QLabel(self.strings[self.current_language]["enter_text_cipher"])
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
        self.select_algorithm_label = QLabel(self.strings[self.current_language]["select_algorithm_level1"])
        self.algorithm = AnimatedComboBox()
        self.algorithm.addItems(["Caesar Cipher", "Vigenere Cipher", "Affine Cipher", "Atbash Cipher", "Reverse String", "Rail Fence Cipher", "Simple Substitution", "Playfair Cipher", "Polybius Square"])
        self.algorithm.currentIndexChanged.connect(self.toggle_algorithm_settings)
        alg_layout.addWidget(self.select_algorithm_label)
        alg_layout.addWidget(self.algorithm)
        layout.addLayout(alg_layout)

        self.alg_settings_widget = QWidget()
        self.alg_settings_layout = QVBoxLayout()
        self.alg_settings_widget.setLayout(self.alg_settings_layout)
        layout.addWidget(self.alg_settings_widget)

        self.caesar_widget = QWidget()
        caesar_layout = QHBoxLayout()
        self.caesar_shift_label = QLabel(self.strings[self.current_language]["caesar_shift_label"])
        self.caesar_shift_spinbox = QSpinBox()
        self.caesar_shift_spinbox.setRange(0, 100)
        self.caesar_shift_spinbox.setValue(3)
        caesar_layout.addWidget(self.caesar_shift_label)
        caesar_layout.addWidget(self.caesar_shift_spinbox)
        self.caesar_widget.setLayout(caesar_layout)
        self.caesar_widget.setVisible(True)

        self.vigenere_widget = QWidget()
        vigenere_layout = QHBoxLayout()
        self.vigenere_key_label = QLabel(self.strings[self.current_language]["vigenere_key_label"])
        self.vigenere_key_entry = QLineEdit()
        vigenere_layout.addWidget(self.vigenere_key_label)
        vigenere_layout.addWidget(self.vigenere_key_entry)
        self.vigenere_widget.setLayout(vigenere_layout)
        self.vigenere_widget.setVisible(False)

        self.affine_widget = QWidget()
        affine_layout = QVBoxLayout()
        self.affine_widget.setLayout(affine_layout)
        affine_a_layout = QHBoxLayout()
        self.affine_a_label = QLabel(self.strings[self.current_language]["affine_a_label"])
        self.affine_a_spinbox = QSpinBox()
        self.affine_a_spinbox.setRange(1, 100)
        self.affine_a_spinbox.setValue(5)
        affine_a_layout.addWidget(self.affine_a_label)
        affine_a_layout.addWidget(self.affine_a_spinbox)
        affine_b_layout = QHBoxLayout()
        self.affine_b_label = QLabel(self.strings[self.current_language]["affine_b_label"])
        self.affine_b_spinbox = QSpinBox()
        self.affine_b_spinbox.setRange(0, 100)
        self.affine_b_spinbox.setValue(8)
        affine_b_layout.addWidget(self.affine_b_label)
        affine_b_layout.addWidget(self.affine_b_spinbox)
        affine_layout.addLayout(affine_a_layout)
        affine_layout.addLayout(affine_b_layout)
        self.affine_widget.setVisible(False)

        self.rail_fence_widget = QWidget()
        rail_fence_layout = QHBoxLayout()
        self.rail_fence_rails_label = QLabel(self.strings[self.current_language]["rail_fence_rails_label"])
        self.rail_fence_rails_spinbox = QSpinBox()
        self.rail_fence_rails_spinbox.setRange(1, 10)
        self.rail_fence_rails_spinbox.setValue(3)
        rail_fence_layout.addWidget(self.rail_fence_rails_label)
        rail_fence_layout.addWidget(self.rail_fence_rails_spinbox)
        self.rail_fence_widget.setLayout(rail_fence_layout)
        self.rail_fence_widget.setVisible(False)

        self.substitution_widget = QWidget()
        substitution_layout = QHBoxLayout()
        self.substitution_key_label = QLabel(self.strings[self.current_language]["substitution_key_label"])
        self.substitution_key_entry = QLineEdit()
        substitution_layout.addWidget(self.substitution_key_label)
        substitution_layout.addWidget(self.substitution_key_entry)
        self.substitution_widget.setLayout(substitution_layout)
        self.substitution_widget.setVisible(False)

        self.playfair_widget = QWidget()
        playfair_layout = QHBoxLayout()
        self.playfair_key_label = QLabel(self.strings[self.current_language]["playfair_key_label"])
        self.playfair_key_entry = QLineEdit()
        playfair_layout.addWidget(self.playfair_key_label)
        playfair_layout.addWidget(self.playfair_key_entry)
        self.playfair_widget.setLayout(playfair_layout)
        self.playfair_widget.setVisible(False)

        self.polybius_widget = QWidget()  # No settings needed for Polybius
        self.polybius_widget.setVisible(False)

        self.alg_settings_layout.addWidget(self.caesar_widget)
        self.alg_settings_layout.addWidget(self.vigenere_widget)
        self.alg_settings_layout.addWidget(self.affine_widget)
        self.alg_settings_layout.addWidget(self.rail_fence_widget)
        self.alg_settings_layout.addWidget(self.substitution_widget)
        self.alg_settings_layout.addWidget(self.playfair_widget)
        self.alg_settings_layout.addWidget(self.polybius_widget)

        action_layout = QHBoxLayout()
        self.encrypt_button = QPushButton(self.strings[self.current_language]["encrypt_button_level1"])
        self.encrypt_button.clicked.connect(self.encrypt)
        self.decrypt_button = QPushButton(self.strings[self.current_language]["decrypt_button_level1"])
        self.decrypt_button.clicked.connect(self.decrypt)
        action_layout.addWidget(self.encrypt_button)
        action_layout.addWidget(self.decrypt_button)
        layout.addLayout(action_layout)

        self.result_label = QLabel(self.strings[self.current_language]["result_label"])
        self.result_text = QTextEdit()
        self.result_text.setFixedHeight(120)
        layout.addWidget(self.result_label)
        layout.addWidget(self.result_text)
        layout.addStretch()

    def toggle_algorithm_settings(self):
        selected_algorithm = self.algorithm.currentText()
        self.caesar_widget.setVisible(selected_algorithm == "Caesar Cipher")
        self.vigenere_widget.setVisible(selected_algorithm == "Vigenere Cipher")
        self.affine_widget.setVisible(selected_algorithm == "Affine Cipher")
        self.rail_fence_widget.setVisible(selected_algorithm == "Rail Fence Cipher")
        self.substitution_widget.setVisible(selected_algorithm == "Simple Substitution")
        self.playfair_widget.setVisible(selected_algorithm == "Playfair Cipher")
        self.polybius_widget.setVisible(selected_algorithm == "Polybius Square")

    def encrypt(self):
        text = self.input_entry.text()
        algorithm = self.algorithm.currentText()
        try:
            if algorithm == "Caesar Cipher":
                shift = self.caesar_shift_spinbox.value()
                result = CryptoUtils.caesar_cipher_encrypt(text, shift)
            elif algorithm == "Vigenere Cipher":
                key = self.vigenere_key_entry.text()
                result = CryptoUtils.vigenere_cipher_encrypt(text, key)
            elif algorithm == "Affine Cipher":
                a_key = self.affine_a_spinbox.value()
                b_key = self.affine_b_spinbox.value()
                result = CryptoUtils.affine_cipher_encrypt(text, a_key, b_key)
            elif algorithm == "Atbash Cipher":
                result = CryptoUtils.atbash_cipher_encrypt(text)
            elif algorithm == "Reverse String":
                result = CryptoUtils.reverse_string(text)
            elif algorithm == "Rail Fence Cipher":
                rails = self.rail_fence_rails_spinbox.value()
                result = CryptoUtils.rail_fence_encrypt(text, rails)
            elif algorithm == "Simple Substitution":
                key = self.substitution_key_entry.text()
                result = CryptoUtils.simple_substitution_encrypt(text, key)
            elif algorithm == "Playfair Cipher":
                key = self.playfair_key_entry.text()
                result = CryptoUtils.playfair_encrypt(text, key)
            elif algorithm == "Polybius Square":
                result = CryptoUtils.polybius_encrypt(text)
            self.result_text.setText(result)
        except ValueError as e:
            QMessageBox.critical(self, self.strings[self.current_language]["algorithm_error_title"], str(e))

    def decrypt(self):
        text = self.input_entry.text()
        algorithm = self.algorithm.currentText()
        try:
            if algorithm == "Caesar Cipher":
                shift = self.caesar_shift_spinbox.value()
                result = CryptoUtils.caesar_cipher_decrypt(text, shift)
            elif algorithm == "Vigenere Cipher":
                key = self.vigenere_key_entry.text()
                result = CryptoUtils.vigenere_cipher_decrypt(text, key)
            elif algorithm == "Affine Cipher":
                a_key = self.affine_a_spinbox.value()
                b_key = self.affine_b_spinbox.value()
                result = CryptoUtils.affine_cipher_decrypt(text, a_key, b_key)
            elif algorithm == "Atbash Cipher":
                result = CryptoUtils.atbash_cipher_decrypt(text)
            elif algorithm == "Reverse String":
                result = CryptoUtils.reverse_string(text)
            elif algorithm == "Rail Fence Cipher":
                rails = self.rail_fence_rails_spinbox.value()
                result = CryptoUtils.rail_fence_decrypt(text, rails)
            elif algorithm == "Simple Substitution":
                key = self.substitution_key_entry.text()
                result = CryptoUtils.simple_substitution_decrypt(text, key)
            elif algorithm == "Playfair Cipher":
                key = self.playfair_key_entry.text()
                result = CryptoUtils.playfair_decrypt(text, key)
            elif algorithm == "Polybius Square":
                result = CryptoUtils.polybius_decrypt(text)
            self.result_text.setText(result)
        except ValueError as e:
            QMessageBox.critical(self, self.strings[self.current_language]["algorithm_error_title"], str(e))

    def clear_text(self):
        self.input_entry.clear()
        self.result_text.clear()
        self.vigenere_key_entry.clear()
        self.substitution_key_entry.clear()
        self.playfair_key_entry.clear()

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
        self.enter_text_label.setText(self.strings[self.current_language]["enter_text_cipher"])
        self.clear_button.setText(self.strings[self.current_language]["clear_button"])
        self.copy_input_button.setText(self.strings[self.current_language]["copy_input_button"])
        self.paste_button.setText(self.strings[self.current_language]["paste_button"])
        self.copy_output_button.setText(self.strings[self.current_language]["copy_output_button"])
        self.select_algorithm_label.setText(self.strings[self.current_language]["select_algorithm_level1"])
        self.caesar_shift_label.setText(self.strings[self.current_language]["caesar_shift_label"])
        self.vigenere_key_label.setText(self.strings[self.current_language]["vigenere_key_label"])
        self.affine_a_label.setText(self.strings[self.current_language]["affine_a_label"])
        self.affine_b_label.setText(self.strings[self.current_language]["affine_b_label"])
        self.rail_fence_rails_label.setText(self.strings[self.current_language]["rail_fence_rails_label"])
        self.substitution_key_label.setText(self.strings[self.current_language]["substitution_key_label"])
        self.playfair_key_label.setText(self.strings[self.current_language]["playfair_key_label"])
        self.encrypt_button.setText(self.strings[self.current_language]["encrypt_button_level1"])
        self.decrypt_button.setText(self.strings[self.current_language]["decrypt_button_level1"])
        self.result_label.setText(self.strings[self.current_language]["result_label"])