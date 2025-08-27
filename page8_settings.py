from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextEdit, QColorDialog, QCheckBox
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt
from animated_combobox import AnimatedComboBox
from toggle_switch import ToggleSwitch

class Page8Settings(QWidget):
    def __init__(self, parent=None, language="English", strings=None):
        super().__init__(parent)
        self.current_language = language
        self.strings = strings
        self.parent_app = parent
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        theme_layout = QHBoxLayout()
        self.theme_label = QLabel(self.strings[self.current_language]["theme_settings_label"])
        self.toggle_switch = ToggleSwitch(self)
        self.toggle_switch.checked = self.parent_app.is_dark
        theme_layout.addWidget(self.theme_label)
        theme_layout.addWidget(self.toggle_switch)
        layout.addLayout(theme_layout)

        lang_layout = QHBoxLayout()
        self.language_label = QLabel(self.strings[self.current_language]["language_settings_label"])
        self.select_language_label = QLabel(self.strings[self.current_language]["select_language_label"])
        self.language_combo = AnimatedComboBox()
        self.language_combo.addItems(["English", "Persian", "Arabic"])
        self.language_combo.setCurrentText(self.current_language)
        self.language_combo.currentTextChanged.connect(self.change_language)
        lang_layout.addWidget(self.select_language_label)
        lang_layout.addWidget(self.language_combo)
        layout.addLayout(lang_layout)

        color_layout = QVBoxLayout()
        self.color_settings_label = QLabel(self.strings[self.current_language]["color_settings_label"])
        color_layout.addWidget(self.color_settings_label)

        button_color_layout = QHBoxLayout()
        self.button_color_label = QLabel(self.strings[self.current_language]["button_color_label"])
        self.color_button = QPushButton(self.strings[self.current_language]["select_color_button"])
        self.color_button.clicked.connect(self.select_color)
        self.use_system_colors = QCheckBox(self.strings[self.current_language]["use_system_colors_label"])
        self.use_system_colors.stateChanged.connect(self.toggle_system_colors)
        button_color_layout.addWidget(self.button_color_label)
        button_color_layout.addWidget(self.color_button)
        button_color_layout.addWidget(self.use_system_colors)
        color_layout.addLayout(button_color_layout)
        layout.addLayout(color_layout)

        about_layout = QVBoxLayout()
        self.about_label = QLabel(self.strings[self.current_language]["about_crypto_coder"])
        self.about_text = QTextEdit(self.strings[self.current_language]["about_text"])
        self.about_text.setReadOnly(True)
        self.about_text.setFixedHeight(150)
        about_layout.addWidget(self.about_label)
        about_layout.addWidget(self.about_text)
        layout.addLayout(about_layout)
        layout.addStretch()

    def select_color(self):
        """باز کردن دیالوگ انتخاب رنگ"""
        color = QColorDialog.getColor()
        if color.isValid() and self.parent_app:
            self.parent_app.set_button_color(color.name())
            self.use_system_colors.setChecked(False)

    def toggle_system_colors(self, state):
        """فعال/غیرفعال کردن استفاده از رنگ سیستم"""
        if self.parent_app:
            self.parent_app.set_use_system_color(state == Qt.CheckState.Checked.value)
            self.color_button.setEnabled(not state)

    def change_language(self, language):
        """تغییر زبان"""
        if self.parent_app:
            self.parent_app.change_language(language)

    def update_language(self, language):
        """به‌روزرسانی زبان صفحه"""
        self.current_language = language
        self.theme_label.setText(self.strings[self.current_language]["theme_settings_label"])
        self.language_label.setText(self.strings[self.current_language]["language_settings_label"])
        self.select_language_label.setText(self.strings[self.current_language]["select_language_label"])
        self.color_settings_label.setText(self.strings[self.current_language]["color_settings_label"])
        self.button_color_label.setText(self.strings[self.current_language]["button_color_label"])
        self.color_button.setText(self.strings[self.current_language]["select_color_button"])
        self.use_system_colors.setText(self.strings[self.current_language]["use_system_colors_label"])
        self.about_label.setText(self.strings[self.current_language]["about_crypto_coder"])
        self.about_text.setText(self.strings[self.current_language]["about_text"])

    def update_styles(self):
        """به‌روزرسانی استایل‌های صفحه"""
        self.setStyleSheet(self.parent_app.styleSheet())