import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QTabWidget, QVBoxLayout, QWidget
from PyQt6.QtGui import QFont, QIcon, QPalette, QColor
from PyQt6.QtCore import Qt
from language_strings import english_strings, persian_strings, arabic_strings
from page1_ciphers import Page1Ciphers
from page2_encoders_decoders import Page2EncodersDecoders
from page3_hashers import Page3Hashers
from page4_advanced_encryption import Page4AdvancedEncryption
from page5_smart_decrypt import Page5SmartDecrypt
from page6_algorithm_mixer import Page6AlgorithmMixer
from page7_file_encryption import Page7FileEncryption
from page8_settings import Page8Settings
import subprocess

class CryptoCoderApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.clipboard = QApplication.clipboard()
        self.current_language = "English"
        self.strings = {
            "English": english_strings,
            "Persian": persian_strings,
            "Arabic": arabic_strings
        }
        self.is_dark = self.detect_system_theme()  # تشخیص تم سیستم
        self.button_color = "#4fc3f7"  # رنگ پیش‌فرض دکمه‌ها
        self.use_system_color = False  # پیش‌فرض: استفاده از رنگ سفارشی
        self.pages = []  # لیست صفحات برای به‌روزرسانی استایل‌ها
        self.init_ui()
        self.setWindowTitle("Crypto Coder")
        self.setGeometry(100, 100, 800, 600)
        self.setWindowIcon(QIcon("Images/Icon.ico"))

    def detect_system_theme(self):
        """تشخیص تم سیستم (روشن یا تیره)"""
        palette = self.palette()
        background = palette.color(QPalette.ColorRole.Window).lightness()
        is_dark = background < 128  # اگر روشنایی کم باشد، تم تیره است
        try:
            # بررسی تم GNOME با gsettings
            result = subprocess.check_output(
                ["gsettings", "get", "org.gnome.desktop.interface", "gtk-theme"],
                text=True
            ).strip()
            if "dark" in result.lower():
                is_dark = True
        except:
            pass  # در ویندوز یا اگر gsettings در دسترس نباشد، از QPalette استفاده می‌شود
        return is_dark

    def get_system_button_color(self):
        """استخراج رنگ برجسته سیستم"""
        return self.palette().color(QPalette.ColorRole.Highlight).name()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        self.tabs = QTabWidget()
        self.tabs.setFont(QFont("Segoe UI", 12))
        layout.addWidget(self.tabs)

        # Initialize pages
        self.page1 = Page1Ciphers(self, self.current_language, self.strings)
        self.page2 = Page2EncodersDecoders(self, self.current_language, self.strings)
        self.page3 = Page3Hashers(self, self.current_language, self.strings)
        self.page4 = Page4AdvancedEncryption(self, self.current_language, self.strings)
        self.page5 = Page5SmartDecrypt(self, self.current_language, self.strings)
        self.page6 = Page6AlgorithmMixer(self, self.current_language, self.strings)
        self.page7 = Page7FileEncryption(self, self.current_language, self.strings)
        self.page8 = Page8Settings(self, self.current_language, self.strings)

        # Add pages to list for style updates
        self.pages = [self.page1, self.page2, self.page3, self.page4, self.page5, self.page6, self.page7, self.page8]

        # Add tabs with initial language labels
        self.tabs.addTab(self.page1, self.strings[self.current_language]["level1_tab"])
        self.tabs.addTab(self.page2, self.strings[self.current_language]["level2_tab"])
        self.tabs.addTab(self.page3, self.strings[self.current_language]["level3_tab"])
        self.tabs.addTab(self.page4, self.strings[self.current_language]["level4_tab"])
        self.tabs.addTab(self.page5, self.strings[self.current_language]["level5_tab"])
        self.tabs.addTab(self.page6, self.strings[self.current_language]["level6_tab"])
        self.tabs.addTab(self.page7, self.strings[self.current_language]["file_encryption_tab"])
        self.tabs.addTab(self.page8, self.strings[self.current_language]["settings_tab"])

        self.apply_styles()

    def apply_styles(self):
        """اعمال استایل‌شیت به کل برنامه"""
        button_color = self.get_system_button_color() if self.use_system_color else self.button_color
        if self.is_dark:
            stylesheet = f"""
                QMainWindow {{
                    background-color: #1e1e2e;
                    color: #e0e0e0;
                    font-family: 'Segoe UI', sans-serif;
                }}
                QWidget {{
                    background-color: #1e1e2e;
                    color: #e0e0e0;
                    font-family: 'Segoe UI', sans-serif;
                }}
                QTabWidget::pane {{
                    border: 1px solid #2a2a3a;
                    background: #2a2a3a;
                    border-radius: 10px;
                }}
                QTabBar::tab {{
                    background: #2a2a3a;
                    color: #e0e0e0;
                    padding: 12px 24px;
                    margin: 2px;
                    border-radius: 8px;
                }}
                QTabBar::tab:selected {{
                    background: {button_color};
                    color: #ffffff;
                }}
                QLineEdit, QTextEdit {{
                    background-color: #2a2a3a;
                    color: #e0e0e0;
                    border: 1px solid #3a3a4a;
                    border-radius: 8px;
                    padding: 8px;
                }}
                QPushButton {{
                    background-color: {button_color};
                    color: #ffffff;
                    border: none;
                    border-radius: 8px;
                    padding: 12px;
                }}
                QPushButton:hover {{
                    background-color: {self.adjust_color_brightness(button_color, 0.8)};
                }}
                QComboBox {{
                    background-color: #2a2a3a;
                    color: #e0e0e0;
                    border: 1px solid #3a3a4a;
                    border-radius: 8px;
                    padding: 8px;
                }}
                QComboBox::drop-down {{
                    border: none;
                    width: 30px;
                }}
                QComboBox QAbstractItemView {{
                    background-color: #2a2a3a;
                    color: #e0e0e0;
                    selection-background-color: {self.adjust_color_brightness(button_color, 0.9)};
                    border: 1px solid #3a3a4a;
                }}
                QScrollArea {{
                    background-color: #1e1e2e;
                    border: none;
                }}
                QScrollBar:vertical {{
                    background: #2a2a3a;
                    width: 12px;
                    margin: 0px;
                    border-radius: 6px;
                }}
                QScrollBar::handle:vertical {{
                    background: {button_color};
                    border-radius: 6px;
                }}
                QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                    height: 0px;
                }}
                QSpinBox {{
                    background-color: #2a2a3a;
                    color: #e0e0e0;
                    border: 1px solid #3a3a4a;
                    border-radius: 8px;
                    padding: 8px;
                }}
                QLabel {{
                    font-size: 14px;
                    color: #e0e0e0;
                }}
                QCheckBox {{
                    color: #e0e0e0;
                }}
            """
        else:
            stylesheet = f"""
                QMainWindow {{
                    background-color: #f0f0f5;
                    color: #333333;
                    font-family: 'Segoe UI', sans-serif;
                }}
                QWidget {{
                    background-color: #f0f0f5;
                    color: #333333;
                    font-family: 'Segoe UI', sans-serif;
                }}
                QTabWidget::pane {{
                    border: 1px solid #d0d0d5;
                    background: #ffffff;
                    border-radius: 10px;
                }}
                QTabBar::tab {{
                    background: #ffffff;
                    color: #333333;
                    padding: 12px 24px;
                    margin: 2px;
                    border-radius: 8px;
                }}
                QTabBar::tab:selected {{
                    background: {button_color};
                    color: #ffffff;
                }}
                QLineEdit, QTextEdit {{
                    background-color: #ffffff;
                    color: #333333;
                    border: 1px solid #d0d0d5;
                    border-radius: 8px;
                    padding: 8px;
                }}
                QPushButton {{
                    background-color: {button_color};
                    color: #ffffff;
                    border: none;
                    border-radius: 8px;
                    padding: 12px;
                }}
                QPushButton:hover {{
                    background-color: {self.adjust_color_brightness(button_color, 0.8)};
                }}
                QComboBox {{
                    background-color: #ffffff;
                    color: #333333;
                    border: 1px solid #d0d0d5;
                    border-radius: 8px;
                    padding: 8px;
                }}
                QComboBox::drop-down {{
                    border: none;
                    width: 30px;
                }}
                QComboBox QAbstractItemView {{
                    background-color: #ffffff;
                    color: #333333;
                    selection-background-color: {self.adjust_color_brightness(button_color, 0.9)};
                    border: 1px solid #d0d0d5;
                }}
                QScrollArea {{
                    background-color: #f0f0f5;
                    border: none;
                }}
                QScrollBar:vertical {{
                    background: #d0d0d5;
                    width: 12px;
                    margin: 0px;
                    border-radius: 6px;
                }}
                QScrollBar::handle:vertical {{
                    background: {button_color};
                    border-radius: 6px;
                }}
                QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                    height: 0px;
                }}
                QSpinBox {{
                    background-color: #ffffff;
                    color: #333333;
                    border: 1px solid #d0d0d5;
                    border-radius: 8px;
                    padding: 8px;
                }}
                QLabel {{
                    font-size: 14px;
                    color: #333333;
                }}
                QCheckBox {{
                    color: #333333;
                }}
            """
        self.setStyleSheet(stylesheet)
        # به‌روزرسانی استایل‌ها در تمام صفحات
        for page in self.pages:
            if hasattr(page, 'update_styles'):
                page.update_styles()

    def toggle_theme(self):
        """تغییر تم و به‌روزرسانی استایل‌ها"""
        self.is_dark = not self.is_dark
        self.apply_styles()

    def set_button_color(self, color):
        """تنظیم رنگ دکمه و به‌روزرسانی استایل‌ها"""
        self.button_color = color if color else self.get_system_button_color()
        self.use_system_color = (color is None)
        self.apply_styles()

    def set_use_system_color(self, use_system):
        """فعال/غیرفعال کردن استفاده از رنگ سیستم"""
        self.use_system_color = use_system
        self.apply_styles()

    def adjust_color_brightness(self, color, factor):
        """تنظیم روشنایی رنگ برای حالت hover"""
        qcolor = QColor(color)
        h, s, v, a = qcolor.getHsvF()
        v = min(1.0, v * factor)
        qcolor.setHsvF(h, s, v, a)
        return qcolor.name()

    def change_language(self, language):
        """تغییر زبان و به‌روزرسانی تب‌ها"""
        self.current_language = language
        self.tabs.setTabText(0, self.strings[language]["level1_tab"])
        self.tabs.setTabText(1, self.strings[language]["level2_tab"])
        self.tabs.setTabText(2, self.strings[language]["level3_tab"])
        self.tabs.setTabText(3, self.strings[language]["level4_tab"])
        self.tabs.setTabText(4, self.strings[language]["level5_tab"])
        self.tabs.setTabText(5, self.strings[language]["level6_tab"])
        self.tabs.setTabText(6, self.strings[language]["file_encryption_tab"])
        self.tabs.setTabText(7, self.strings[language]["settings_tab"])
        for page in self.pages:
            if hasattr(page, 'update_language'):
                page.update_language(language)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = CryptoCoderApp()
    window.show()
    sys.exit(app.exec())