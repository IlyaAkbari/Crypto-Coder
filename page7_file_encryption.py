from PyQt6.QtWidgets import QWidget, QApplication, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QFileDialog, QMessageBox, QGraphicsDropShadowEffect
from PyQt6.QtGui import QFont, QColor
from animated_combobox import AnimatedComboBox
from crypto_utils import CryptoUtils
import os
import mimetypes

class Page7FileEncryption(QWidget):
    def __init__(self, parent=None, language="English", strings=None):
        super().__init__(parent)
        self.current_language = language
        self.strings = strings or {}
        self.crypto_utils = CryptoUtils(language=self.current_language, strings=self.strings)
        self.parent_app = parent
        self.selected_file = None
        self.selected_folder = None
        self.output_folder = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        # Algorithm selection
        alg_layout = QHBoxLayout()
        self.select_algorithm_label = QLabel(self.strings.get(self.current_language, {}).get("select_algorithm_file", "Select Algorithm"))
        self.select_algorithm_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        self.algorithm = AnimatedComboBox()
        self.algorithm.addItems(["AES", "Blowfish", "ChaCha20", "TripleDES"])
        alg_layout.addWidget(self.select_algorithm_label)
        alg_layout.addWidget(self.algorithm)
        layout.addLayout(alg_layout)

        # Symmetric key input
        key_layout = QHBoxLayout()
        self.symmetric_key_label = QLabel(self.strings.get(self.current_language, {}).get("symmetric_key_label", "Symmetric Key"))
        self.symmetric_key_label.setFont(QFont("Segoe UI", 12))
        self.symmetric_key_entry = QLineEdit()
        self.symmetric_key_entry.setFont(QFont("Segoe UI", 12))
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(10)
        shadow.setColor(QColor(0, 0, 0, 50))
        self.symmetric_key_entry.setGraphicsEffect(shadow)
        key_layout.addWidget(self.symmetric_key_label)
        key_layout.addWidget(self.symmetric_key_entry)
        layout.addLayout(key_layout)

        # File selection
        file_layout = QHBoxLayout()
        self.select_file_button = QPushButton(self.strings.get(self.current_language, {}).get("select_file_button", "Select File"))
        self.select_file_button.clicked.connect(self.select_file)
        self.selected_file_label = QLabel(self.strings.get(self.current_language, {}).get("no_file_selected", "No file selected"))
        file_layout.addWidget(self.select_file_button)
        file_layout.addWidget(self.selected_file_label)
        layout.addLayout(file_layout)

        # Folder selection
        folder_layout = QHBoxLayout()
        self.select_folder_button = QPushButton(self.strings.get(self.current_language, {}).get("select_folder_button", "Select Folder"))
        self.select_folder_button.clicked.connect(self.select_folder)
        self.selected_folder_label = QLabel(self.strings.get(self.current_language, {}).get("no_file_selected", "No folder selected"))
        folder_layout.addWidget(self.select_folder_button)
        folder_layout.addWidget(self.selected_folder_label)
        layout.addLayout(folder_layout)

        # Key generator settings
        key_gen_layout = QVBoxLayout()
        self.key_generator_label = QLabel(self.strings.get(self.current_language, {}).get("key_generator_settings_label", "Key Generator Settings"))
        self.key_generator_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        key_gen_layout.addWidget(self.key_generator_label)

        # Symmetric key generation
        sym_key_layout = QHBoxLayout()
        self.key_size_label = QLabel(self.strings.get(self.current_language, {}).get("key_size_label", "Key Size (bits)"))
        self.key_size_entry = QLineEdit("256")
        self.key_size_entry.setFixedWidth(100)
        self.generate_key_button = QPushButton(self.strings.get(self.current_language, {}).get("generate_key_button", "Generate Key"))
        self.generate_key_button.clicked.connect(self.generate_symmetric_key)
        self.key_result_label = QLabel(self.strings.get(self.current_language, {}).get("key_result_label", "Generated Key"))
        self.key_result = QLineEdit()
        self.key_result.setReadOnly(True)
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(10)
        shadow.setColor(QColor(0, 0, 0, 50))
        self.key_result.setGraphicsEffect(shadow)
        self.copy_key_button = QPushButton(self.strings.get(self.current_language, {}).get("copy_key_button", "Copy Key"))
        self.copy_key_button.clicked.connect(self.copy_key)
        sym_key_layout.addWidget(self.key_size_label)
        sym_key_layout.addWidget(self.key_size_entry)
        sym_key_layout.addWidget(self.generate_key_button)
        sym_key_layout.addWidget(self.key_result_label)
        sym_key_layout.addWidget(self.key_result)
        sym_key_layout.addWidget(self.copy_key_button)
        key_gen_layout.addLayout(sym_key_layout)

        layout.addLayout(key_gen_layout)

        # Action buttons
        action_layout = QHBoxLayout()
        self.encrypt_button = QPushButton(self.strings.get(self.current_language, {}).get("encrypt_button_file", "Encrypt"))
        self.encrypt_button.clicked.connect(self.encrypt)
        self.decrypt_button = QPushButton(self.strings.get(self.current_language, {}).get("decrypt_button_file", "Decrypt"))
        self.decrypt_button.clicked.connect(self.decrypt)
        action_layout.addWidget(self.encrypt_button)
        action_layout.addWidget(self.decrypt_button)
        layout.addLayout(action_layout)
        layout.addStretch()

    def select_file(self):
        file_dialog = QFileDialog(self)
        file_path, _ = file_dialog.getOpenFileName(self, "Select File", "", "All Files (*.*);;MP3 Files (*.mp3);;Text Files (*.txt);;Image Files (*.png *.jpg *.jpeg);;Video Files (*.mp4 *.avi)")
        if file_path and os.path.exists(file_path):
            self.selected_file = file_path
            self.selected_file_label.setText(f"{self.strings.get(self.current_language, {}).get('file_selected', 'File selected:')} {os.path.basename(file_path)}")
            self.selected_file_label.setToolTip(file_path)
            self.selected_folder = None
            self.selected_folder_label.setText(self.strings.get(self.current_language, {}).get("no_file_selected", "No folder selected"))
            self.select_folder_button.setEnabled(False)
            self.select_file_button.setEnabled(True)
            print(f"Selected file: {self.selected_file}")
        else:
            self.selected_file = None
            self.selected_file_label.setText(self.strings.get(self.current_language, {}).get("no_file_selected", "No file selected"))
            self.select_folder_button.setEnabled(True)
            print("No file selected")
        return bool(self.selected_file)

    def select_folder(self):
        folder_dialog = QFileDialog(self)
        folder_path = folder_dialog.getExistingDirectory(self, "Select Folder for Encryption/Decryption")
        if folder_path and os.path.isdir(folder_path):
            self.selected_folder = folder_path
            self.selected_folder_label.setText(f"{self.strings.get(self.current_language, {}).get('file_selected', 'Folder selected:')} {folder_path}")
            self.selected_folder_label.setToolTip(folder_path)
            self.selected_file = None
            self.selected_file_label.setText(self.strings.get(self.current_language, {}).get("no_file_selected", "No file selected"))
            self.select_file_button.setEnabled(False)
            self.select_folder_button.setEnabled(True)
            print(f"Selected folder: {self.selected_folder}")
            return True
        else:
            self.selected_folder = None
            self.selected_folder_label.setText(self.strings.get(self.current_language, {}).get("no_file_selected", "No folder selected"))
            self.select_file_button.setEnabled(True)
            print("No folder selected")
            return False

    def select_output_folder(self):
        folder_dialog = QFileDialog(self)
        folder_path = folder_dialog.getExistingDirectory(self, "Select Output Folder")
        if folder_path and os.path.isdir(folder_path):
            self.output_folder = folder_path
            print(f"Selected output folder: {self.output_folder}")
            return True
        else:
            self.output_folder = None
            print("No output folder selected")
            return False

    def generate_symmetric_key(self):
        try:
            key_size = int(self.key_size_entry.text().strip())
            if key_size <= 0:
                raise ValueError("key_generation_error_title")
            key = self.crypto_utils.generate_key(key_size)
            self.key_result.setText(key)
            self.symmetric_key_entry.setText(key)
        except ValueError as e:
            error_title = self.strings.get(self.current_language, {}).get("algorithm_error_title", "Error")
            error_message = self.crypto_utils.get_error_message(str(e))
            QMessageBox.critical(self, error_title, error_message)

    def copy_key(self):
        key = self.key_result.text()
        if key:
            QApplication.clipboard().setText(key)
            QMessageBox.information(self, "Clipboard", self.strings.get(self.current_language, {}).get("key_copied_clipboard", "Key copied to clipboard"))
        else:
            QMessageBox.warning(self, "Clipboard", self.strings.get(self.current_language, {}).get("clipboard_empty", "No key to copy"))

    def encrypt(self):
        if not self.selected_file and not self.selected_folder:
            QMessageBox.warning(self,
                               self.strings.get(self.current_language, {}).get("algorithm_error_title", "Error"),
                               self.strings.get(self.current_language, {}).get("select_file_or_folder", "Please select a file or folder first"))
            return
        if not self.select_output_folder():
            QMessageBox.warning(self,
                               self.strings.get(self.current_language, {}).get("algorithm_error_title", "Error"),
                               self.strings.get(self.current_language, {}).get("select_output_folder", "Please select an output folder"))
            return
        key = self.symmetric_key_entry.text().strip()
        if not key:
            QMessageBox.critical(self,
                                self.strings.get(self.current_language, {}).get("algorithm_error_title", "Error"),
                                self.strings.get(self.current_language, {}).get("key_empty", "Key cannot be empty"))
            return
        try:
            algorithm = self.algorithm.currentText()
            key_bytes = bytes.fromhex(key)
            processed_files = 0
            if self.selected_file:
                # رمزنگاری فایل تکی
                with open(self.selected_file, 'rb') as f:
                    data = f.read()
                file_extension = os.path.splitext(self.selected_file)[1] or mimetypes.guess_extension(mimetypes.guess_type(self.selected_file)[0]) or ''
                if algorithm == "AES":
                    if len(key_bytes) not in [16, 24, 32]:
                        raise ValueError("invalid_aes_key")
                    encrypted_data = self.crypto_utils.aes_encrypt_binary(data, key_bytes, file_extension)
                elif algorithm == "Blowfish":
                    if len(key_bytes) < 4 or len(key_bytes) > 56:
                        raise ValueError("invalid_blowfish_key")
                    encrypted_data = self.crypto_utils.blowfish_encrypt_binary(data, key_bytes, file_extension)
                elif algorithm == "ChaCha20":
                    if len(key_bytes) != 32:
                        raise ValueError("invalid_chacha20_key")
                    encrypted_data = self.crypto_utils.chacha20_encrypt_binary(data, key_bytes, file_extension)
                elif algorithm == "TripleDES":
                    if len(key_bytes) not in [16, 24]:
                        raise ValueError("invalid_tripledes_key")
                    encrypted_data = self.crypto_utils.tripledes_encrypt_binary(data, key_bytes, file_extension)
                # استفاده از نام فایل بدون پسوند اصلی
                base_name = os.path.splitext(os.path.basename(self.selected_file))[0]
                output_path = os.path.join(self.output_folder, f"{base_name}.crpt")
                with open(output_path, 'wb') as f:
                    f.write(encrypted_data)
                processed_files += 1
                print(f"Encrypted file: {output_path}")
            elif self.selected_folder:
                # رمزنگاری تمام فایل‌های پوشه
                for root, _, files in os.walk(self.selected_folder):
                    for file_name in files:
                        file_path = os.path.join(root, file_name)
                        try:
                            with open(file_path, 'rb') as f:
                                data = f.read()
                            file_extension = os.path.splitext(file_name)[1] or mimetypes.guess_extension(mimetypes.guess_type(file_path)[0]) or ''
                            if algorithm == "AES":
                                if len(key_bytes) not in [16, 24, 32]:
                                    raise ValueError("invalid_aes_key")
                                encrypted_data = self.crypto_utils.aes_encrypt_binary(data, key_bytes, file_extension)
                            elif algorithm == "Blowfish":
                                if len(key_bytes) < 4 or len(key_bytes) > 56:
                                    raise ValueError("invalid_blowfish_key")
                                encrypted_data = self.crypto_utils.blowfish_encrypt_binary(data, key_bytes, file_extension)
                            elif algorithm == "ChaCha20":
                                if len(key_bytes) != 32:
                                    raise ValueError("invalid_chacha20_key")
                                encrypted_data = self.crypto_utils.chacha20_encrypt_binary(data, key_bytes, file_extension)
                            elif algorithm == "TripleDES":
                                if len(key_bytes) not in [16, 24]:
                                    raise ValueError("invalid_tripledes_key")
                                encrypted_data = self.crypto_utils.tripledes_encrypt_binary(data, key_bytes, file_extension)
                            # استفاده از نام فایل بدون پسوند اصلی
                            base_name = os.path.splitext(file_name)[0]
                            output_path = os.path.join(self.output_folder, f"{base_name}.crpt")
                            with open(output_path, 'wb') as f:
                                f.write(encrypted_data)
                            processed_files += 1
                            print(f"Encrypted file: {output_path}")
                        except Exception as e:
                            print(f"Failed to encrypt {file_path}: {str(e)}")
            if processed_files > 0:
                QMessageBox.information(self,
                                       self.strings.get(self.current_language, {}).get("success_title", "Success"),
                                       self.strings.get(self.current_language, {}).get("file_encryption_success", f"Encrypted {processed_files} file(s) successfully"))
            else:
                QMessageBox.warning(self,
                                   self.strings.get(self.current_language, {}).get("algorithm_error_title", "Error"),
                                   self.strings.get(self.current_language, {}).get("no_files_processed", "No files were encrypted"))
        except Exception as e:
            QMessageBox.critical(self,
                                self.strings.get(self.current_language, {}).get("algorithm_error_title", "Error"),
                                f"{self.strings.get(self.current_language, {}).get('file_encryption_error', 'Encryption failed')}: {str(e)}")

    def decrypt(self):
        if not self.selected_file and not self.selected_folder:
            QMessageBox.warning(self,
                               self.strings.get(self.current_language, {}).get("algorithm_error_title", "Error"),
                               self.strings.get(self.current_language, {}).get("select_file_or_folder", "Please select a file or folder first"))
            return
        if not self.select_output_folder():
            QMessageBox.warning(self,
                               self.strings.get(self.current_language, {}).get("algorithm_error_title", "Error"),
                               self.strings.get(self.current_language, {}).get("select_output_folder", "Please select an output folder"))
            return
        key = self.symmetric_key_entry.text().strip()
        if not key:
            QMessageBox.critical(self,
                                self.strings.get(self.current_language, {}).get("algorithm_error_title", "Error"),
                                self.strings.get(self.current_language, {}).get("key_empty", "Key cannot be empty"))
            return
        try:
            algorithm = self.algorithm.currentText()
            key_bytes = bytes.fromhex(key)
            processed_files = 0
            if self.selected_file:
                # رمزگشایی فایل تکی
                if not self.selected_file.endswith('.crpt'):
                    QMessageBox.warning(self,
                                       self.strings.get(self.current_language, {}).get("algorithm_error_title", "Error"),
                                       self.strings.get(self.current_language, {}).get("invalid_file_format", "Selected file must have .crpt extension"))
                    return
                with open(self.selected_file, 'rb') as f:
                    encrypted_data = f.read()
                if algorithm == "AES":
                    if len(key_bytes) not in [16, 24, 32]:
                        raise ValueError("invalid_aes_key")
                    decrypted_data, file_extension = self.crypto_utils.aes_decrypt_binary(encrypted_data, key_bytes)
                elif algorithm == "Blowfish":
                    if len(key_bytes) < 4 or len(key_bytes) > 56:
                        raise ValueError("invalid_blowfish_key")
                    decrypted_data, file_extension = self.crypto_utils.blowfish_decrypt_binary(encrypted_data, key_bytes)
                elif algorithm == "ChaCha20":
                    if len(key_bytes) != 32:
                        raise ValueError("invalid_chacha20_key")
                    decrypted_data, file_extension = self.crypto_utils.chacha20_decrypt_binary(encrypted_data, key_bytes)
                elif algorithm == "TripleDES":
                    if len(key_bytes) not in [16, 24]:
                        raise ValueError("invalid_tripledes_key")
                    decrypted_data, file_extension = self.crypto_utils.tripledes_decrypt_binary(encrypted_data, key_bytes)
                # استفاده از نام فایل بدون .crpt و اضافه کردن پسوند اصلی
                base_name = os.path.splitext(os.path.basename(self.selected_file))[0]
                output_path = os.path.join(self.output_folder, f"{base_name}{file_extension or ''}")
                with open(output_path, 'wb') as f:
                    f.write(decrypted_data)
                processed_files += 1
                print(f"Decrypted file: {output_path}")
            elif self.selected_folder:
                # رمزگشایی تمام فایل‌های .crpt در پوشه
                for root, _, files in os.walk(self.selected_folder):
                    for file_name in files:
                        if not file_name.endswith('.crpt'):
                            continue
                        file_path = os.path.join(root, file_name)
                        try:
                            with open(file_path, 'rb') as f:
                                encrypted_data = f.read()
                            if algorithm == "AES":
                                if len(key_bytes) not in [16, 24, 32]:
                                    raise ValueError("invalid_aes_key")
                                decrypted_data, file_extension = self.crypto_utils.aes_decrypt_binary(encrypted_data, key_bytes)
                            elif algorithm == "Blowfish":
                                if len(key_bytes) < 4 or len(key_bytes) > 56:
                                    raise ValueError("invalid_blowfish_key")
                                decrypted_data, file_extension = self.crypto_utils.blowfish_decrypt_binary(encrypted_data, key_bytes)
                            elif algorithm == "ChaCha20":
                                if len(key_bytes) != 32:
                                    raise ValueError("invalid_chacha20_key")
                                decrypted_data, file_extension = self.crypto_utils.chacha20_decrypt_binary(encrypted_data, key_bytes)
                            elif algorithm == "TripleDES":
                                if len(key_bytes) not in [16, 24]:
                                    raise ValueError("invalid_tripledes_key")
                                decrypted_data, file_extension = self.crypto_utils.tripledes_decrypt_binary(encrypted_data, key_bytes)
                            # استفاده از نام فایل بدون .crpt و اضافه کردن پسوند اصلی
                            base_name = os.path.splitext(file_name)[0]
                            output_path = os.path.join(self.output_folder, f"{base_name}{file_extension or ''}")
                            with open(output_path, 'wb') as f:
                                f.write(decrypted_data)
                            processed_files += 1
                            print(f"Decrypted file: {output_path}")
                        except Exception as e:
                            print(f"Failed to decrypt {file_path}: {str(e)}")
            if processed_files > 0:
                QMessageBox.information(self,
                                       self.strings.get(self.current_language, {}).get("success_title", "Success"),
                                       self.strings.get(self.current_language, {}).get("file_decryption_success", f"Decrypted {processed_files} file(s) successfully"))
            else:
                QMessageBox.warning(self,
                                   self.strings.get(self.current_language, {}).get("algorithm_error_title", "Error"),
                                   self.strings.get(self.current_language, {}).get("no_files_processed", "No files were decrypted"))
        except Exception as e:
            QMessageBox.critical(self,
                                self.strings.get(self.current_language, {}).get("algorithm_error_title", "Error"),
                                f"{self.strings.get(self.current_language, {}).get('file_decryption_error', 'Decryption failed')}: {str(e)}")

    def update_language(self, language):
        self.current_language = language
        self.crypto_utils.language = language
        self.select_algorithm_label.setText(self.strings.get(self.current_language, {}).get("select_algorithm_file", "Select Algorithm"))
        self.symmetric_key_label.setText(self.strings.get(self.current_language, {}).get("symmetric_key_label", "Symmetric Key"))
        self.select_file_button.setText(self.strings.get(self.current_language, {}).get("select_file_button", "Select File"))
        self.select_folder_button.setText(self.strings.get(self.current_language, {}).get("select_folder_button", "Select Folder"))
        self.selected_file_label.setText(self.strings.get(self.current_language, {}).get("no_file_selected", "No file selected") if not self.selected_file else f"{self.strings.get(self.current_language, {}).get('file_selected', 'File selected:')} {os.path.basename(self.selected_file)}")
        self.selected_folder_label.setText(self.strings.get(self.current_language, {}).get("no_file_selected", "No folder selected") if not self.selected_folder else f"{self.strings.get(self.current_language, {}).get('file_selected', 'Folder selected:')} {self.selected_folder}")
        self.encrypt_button.setText(self.strings.get(self.current_language, {}).get("encrypt_button_file", "Encrypt"))
        self.decrypt_button.setText(self.strings.get(self.current_language, {}).get("decrypt_button_file", "Decrypt"))
        self.key_generator_label.setText(self.strings.get(self.current_language, {}).get("key_generator_settings_label", "Key Generator Settings"))
        self.key_size_label.setText(self.strings.get(self.current_language, {}).get("key_size_label", "Key Size (bits)"))
        self.generate_key_button.setText(self.strings.get(self.current_language, {}).get("generate_key_button", "Generate Key"))
        self.key_result_label.setText(self.strings.get(self.current_language, {}).get("key_result_label", "Generated Key"))
        self.copy_key_button.setText(self.strings.get(self.current_language, {}).get("copy_key_button", "Copy Key"))