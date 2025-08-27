from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QPushButton, QMessageBox, QApplication, QScrollArea, QGraphicsDropShadowEffect, QProgressBar, QComboBox
from PyQt6.QtGui import QFont, QColor
from PyQt6.QtCore import QEasingCurve, QPropertyAnimation
from crypto_utils import CryptoUtils
import re
import string
import math
from collections import Counter
import numpy as np
from sklearn.naive_bayes import GaussianNB
import base64
import hashlib
import random
import itertools
from concurrent.futures import ThreadPoolExecutor, as_completed
import numba
from numba import cuda
import multiprocessing
import time
import unicodedata

class Page5SmartDecrypt(QWidget):
    def __init__(self, parent=None, language="English", strings=None):
        super().__init__(parent)
        self.current_language = language
        self.strings = strings or {
            "English": {
                "enter_text_smart_decrypt": "Enter text to decrypt",
                "decrypt_button_level5": "Smart Decrypt",
                "clear_button": "Clear",
                "copy_input_button": "Copy Input",
                "paste_button": "Paste",
                "copy_output_button": "Copy Output",
                "result_label": "Result",
                "algorithm_error_title": "Algorithm Error",
                "clipboard_empty": "Input is empty",
                "hash_detected_title": "Hash Detected",
                "hash_detected_message": "The input appears to be a {0} hash. Attempt to crack it using a dictionary or up to 10,000 random attempts?",
                "hash_cracked_message": "Hash {0} cracked: {1}",
                "hash_cracking_failed": "Failed to crack {0} hash: No match found after {1} attempts.",
                "hash_cracking_error": "Error cracking {0} hash: {1}",
                "key_recovery_failed": "Failed to recover key for {0}: {1}",
                "key_recovery_cipher_message": "Failed to recover key for {0}: Invalid input format.",
                "key_recovery_rsa_message": "RSA decryption requires the private key, not feasible in this version.",
                "key_recovery_symmetric_message": "Brute-forcing {0} key is not supported.",
                "clipboard_output_copied": "Output copied to clipboard",
                "clipboard_input_copied": "Input copied to clipboard",
                "decode_failed": "Failed to decode: No readable output found.\nTried methods: {0}",
                "progress_message": "Processing {0} of {1} methods...",
                "multi_layer_detected": "Multi-layer decryption: {0}",
                "select_method_label": "Select decryption methods",
                "all_methods": "All Methods",
                "classical_ciphers": "Classical Ciphers",
                "modern_ciphers": "Modern Ciphers",
                "hash_methods": "Hash Cracking",
                "no_methods_selected": "No methods selected for decryption.",
                "invalid_input_format": "Invalid input format for {0}.",
                "processing_timeout": "Processing timeout for {0}. Try a smaller input or fewer methods.",
                "base64_decode_error": "Failed to decode Base64: Invalid format.",
                "cancel_button": "Cancel",
                "decryption_cancelled": "Decryption process cancelled.",
                "testing_algorithms": "Testing algorithms from Ciphers and Encoders/Decoders...",
                "result_number": "Best Result:",
                "readability_score": "Readability Score: {0}",
                "algorithm_used": "Algorithm: {0}",
                "no_readable_results": "No readable results found. Try a different input."
            },
            "Persian": {
                "enter_text_smart_decrypt": "متن را برای رمزگشایی وارد کنید",
                "decrypt_button_level5": "رمزگشایی هوشمند",
                "clear_button": "پاک کردن",
                "copy_input_button": "کپی ورودی",
                "paste_button": "جای‌گذاری",
                "copy_output_button": "کپی خروجی",
                "result_label": "نتیجه",
                "algorithm_error_title": "خطای الگوریتم",
                "clipboard_empty": "ورودی خالی است",
                "hash_detected_title": "هش شناسایی شد",
                "hash_detected_message": "ورودی به نظر می‌رسد یک هش {0} باشد. آیا می‌خواهید با دیکشنری یا حداکثر ۱۰,۰۰۰ تلاش تصادفی کرک شود؟",
                "hash_cracked_message": "هش {0} کرک شد: {1}",
                "hash_cracking_failed": "کرک کردن هش {0} ناموفق بود: هیچ تطابقی پس از {1} تلاش یافت نشد.",
                "hash_cracking_error": "خطا در کرک کردن هش {0}: {1}",
                "key_recovery_failed": "بازیابی کلید برای {0} ناموفق بود: {1}",
                "key_recovery_cipher_message": "بازیابی کلید برای {0} ناموفق بود: فرمت ورودی نامعتبر است.",
                "key_recovery_rsa_message": "رمزگشایی RSA نیازمند کلید خصوصی است و در این نسخه امکان‌پذیر نیست.",
                "key_recovery_symmetric_message": "تلاش برای بازیابی کلید {0} پشتیبانی نمی‌شود.",
                "clipboard_output_copied": "خروجی در کلیپ‌بورد کپی شد",
                "clipboard_input_copied": "ورودی در کلیپ‌بورد کپی شد",
                "decode_failed": "رمزگشایی ناموفق بود: خروجی قابل خواندن یافت نشد.\nمتدهای آزمایش‌شده: {0}",
                "progress_message": "در حال پردازش {0} از {1} متد...",
                "multi_layer_detected": "رمزگشایی چندلایه: {0}",
                "select_method_label": "انتخاب روش‌های رمزگشایی",
                "all_methods": "همه روش‌ها",
                "classical_ciphers": "رمزهای کلاسیک",
                "modern_ciphers": "رمزهای مدرن",
                "hash_methods": "کرک کردن هش",
                "no_methods_selected": "هیچ روشی برای رمزگشایی انتخاب نشده است.",
                "invalid_input_format": "فرمت ورودی برای {0} نامعتبر است.",
                "processing_timeout": "زمان پردازش برای {0} به پایان رسید. ورودی کوچک‌تر یا روش‌های کمتری امتحان کنید.",
                "base64_decode_error": "رمزگشایی Base64 ناموفق بود: فرمت نامعتبر.",
                "cancel_button": "لغو",
                "decryption_cancelled": "فرآیند رمزگشایی لغو شد.",
                "testing_algorithms": "در حال تست الگوریتم‌های رمزگذاری و کدگشایی...",
                "result_number": "بهترین نتیجه:",
                "readability_score": "امتیاز خوانایی: {0}",
                "algorithm_used": "الگوریتم استفاده‌شده: {0}",
                "no_readable_results": "هیچ نتیجه خوانایی یافت نشد. ورودی دیگری امتحان کنید."
            },
            "Arabic": {
                "enter_text_smart_decrypt": "أدخل النص لفك تشفيره",
                "decrypt_button_level5": "فك التشفير الذكي",
                "clear_button": "مسح",
                "copy_input_button": "نسخ الإدخال",
                "paste_button": "لصق",
                "copy_output_button": "نسخ الإخراج",
                "result_label": "النتيجة",
                "algorithm_error_title": "خطأ في الخوارزمية",
                "clipboard_empty": "الإدخال فارغ",
                "hash_detected_title": "تم الكشف عن هاش",
                "hash_detected_message": "يبدو أن الإدخال عبارة عن هاش {0}. هل ترغب في محاولة كسره باستخدام قاموس أو ما يصل إلى ١٠٠٠٠ محاولة عشوائية؟",
                "hash_cracked_message": "تم كسر هاش {0}: {1}",
                "hash_cracking_failed": "فشل في كسر هاش {0}: لم يتم العثور على تطابق بعد {1} محاولات.",
                "hash_cracking_error": "خطأ في كسر هاش {0}: {1}",
                "key_recovery_failed": "فشل في استرداد مفتاح {0}: {1}",
                "key_recovery_cipher_message": "فشل في استرداد مفتاح {0}: تنسيق الإدخال غير صالح.",
                "key_recovery_rsa_message": "فك تشفير RSA يتطلب المفتاح الخاص، وهو غير ممكن في هذا الإصدار.",
                "key_recovery_symmetric_message": "محاولة كسر مفتاح {0} غير مدعومة.",
                "clipboard_output_copied": "تم نسخ الإخراج إلى الحافظة",
                "clipboard_input_copied": "تم نسخ الإدخال إلى الحافظة",
                "decode_failed": "فشل فك التشفير: لم يتم العثور على إخراج قابل للقراءة.\nالطرق التي تم تجربتها: {0}",
                "progress_message": "جاري معالجة {0} من {1} طرق...",
                "multi_layer_detected": "تم الكشف عن فك تشفير متعدد الطبقات: {0}",
                "select_method_label": "اختر طرق فك التشفير",
                "all_methods": "جميع الطرق",
                "classical_ciphers": "الشيفرات الكلاسيكية",
                "modern_ciphers": "الشيفرات الحديثة",
                "hash_methods": "كسر الهاش",
                "no_methods_selected": "لم يتم اختيار أي طرق لفك التشفير.",
                "invalid_input_format": "تنسيق الإدخال غير صالح لـ {0}.",
                "processing_timeout": "انتهى وقت المعالجة لـ {0}. جرب إدخالًا أصغر أو طرقًا أقل.",
                "base64_decode_error": "فشل فك تشفير Base64: تنسيق غير صالح.",
                "cancel_button": "إلغاء",
                "decryption_cancelled": "تم إلغاء عملية فك التشفير.",
                "testing_algorithms": "جاري اختبار الخوارزميات من التشفيرات والمشفرات/فك التشفير...",
                "result_number": "أفضل نتيجة:",
                "readability_score": "درجة القراءة: {0}",
                "algorithm_used": "الخوارزمية المستخدمة: {0}",
                "no_readable_results": "لم يتم العثور على نتائج قابلة للقراءة. جرب مدخلًا مختلفًا."
            }
        }
        self.crypto_utils = CryptoUtils(language=self.current_language, strings=self.strings)
        self.cache = {}
        self.is_cancelled = False
        self.init_ui()
        self.parent_app = parent
        self.english_freq = {'e': 0.127, 't': 0.091, 'a': 0.082, 'o': 0.075, 'i': 0.070, 'n': 0.067, 's': 0.063, 'h': 0.061, 'r': 0.060, 'd': 0.043, 'l': 0.040, 'c': 0.028, 'u': 0.028, 'm': 0.024, 'w': 0.024, 'f': 0.022, 'g': 0.020, 'y': 0.020, 'p': 0.019, 'b': 0.015, 'v': 0.010, 'k': 0.008, 'j': 0.002, 'x': 0.002, 'q': 0.001, 'z': 0.001}
        self.persian_freq = {'ا': 0.15, 'ر': 0.09, 'ی': 0.08, 'ن': 0.07, 'د': 0.06, 'م': 0.06, 'و': 0.05, 'ت': 0.05, 'س': 0.04, 'ل': 0.04, 'ه': 0.04, 'ب': 0.03, 'ک': 0.03, 'ش': 0.03, 'ف': 0.02, 'ج': 0.02, 'پ': 0.02, 'خ': 0.01, 'گ': 0.01, 'چ': 0.01}
        self.arabic_freq = {'ا': 0.14, 'ل': 0.10, 'ي': 0.08, 'م': 0.07, 'ن': 0.06, 'ر': 0.06, 'ت': 0.05, 'و': 0.05, 'س': 0.04, 'د': 0.04, 'ب': 0.04, 'ه': 0.03, 'ك': 0.03, 'ف': 0.03, 'ع': 0.02, 'ح': 0.02, 'ج': 0.02, 'ش': 0.01, 'خ': 0.01}
        self.decoding_methods = [
            ("Base64", self.crypto_utils.base64_decode_text, None),
            ("Hex", self.crypto_utils.hex_decode_text, None),
            ("ROT13", self.crypto_utils.rot13_decode_text, None),
            ("Base32", self.crypto_utils.base32_decode_text, None),
            ("UUEncode", self.crypto_utils.uudecode_text, None),
            ("Quoted-Printable", self.crypto_utils.quoted_printable_decode_text, None),
            ("Unicode Escape", self.crypto_utils.unicode_escape_decode_text, None),
            ("ASCII", self.crypto_utils.ascii_decode_text, None),
            ("Binary", self.crypto_utils.binary_decode_text, None),
            ("Morse", self.crypto_utils.morse_decode_text, None),
            ("Polybius", self.crypto_utils.polybius_decrypt, None),
        ]
        self.cipher_methods = [
            ("Caesar", self.crypto_utils.caesar_cipher_decrypt, "shift"),
            ("Vigenere", self.crypto_utils.vigenere_cipher_decrypt, "key"),
            ("Affine", self.crypto_utils.affine_cipher_decrypt, "ab_keys"),
            ("Rail Fence", self.crypto_utils.rail_fence_decrypt, "rails"),
            ("Substitution", self.crypto_utils.simple_substitution_decrypt, "key"),
            ("Playfair", self.crypto_utils.playfair_decrypt, "key"),
            ("Atbash", self.crypto_utils.atbash_cipher_decrypt, None),
            ("Reverse String", self.crypto_utils.reverse_string, None),
        ]
        self.encryption_methods = [
            ("AES", self.crypto_utils.aes_decrypt, "symmetric"),
            ("RSA", self.crypto_utils.rsa_decrypt, "rsa"),
            ("Blowfish", self.crypto_utils.blowfish_decrypt, "symmetric"),
            ("ChaCha20", self.crypto_utils.chacha20_decrypt, "symmetric"),
            ("TripleDES", self.crypto_utils.tripledes_decrypt, "symmetric"),
        ]
        self.hash_algorithms = {
            "MD5": (32, self.md5_hash_cpu),
            "SHA1": (40, self.sha1_hash_cpu),
            "SHA256": (64, self.sha256_hash_cpu),
            "SHA512": (128, self.sha512_hash_cpu),
        }
        self.hash_dictionary = {
            "d41d8cd98f00b204e9800998ecf8427e": ("MD5", ""),
            "098f6bcd4621d373cade4e832627b4f6": ("MD5", "test"),
            "5f4dcc3b5aa765d61d8327deb882cf99": ("MD5", "password"),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709": ("SHA1", ""),
            "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3": ("SHA1", "test"),
            "86fb269d190d2c85f6e0468ceca42a20": ("SHA1", "password"),
            "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae": ("SHA256", "foo"),
            "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e": ("SHA256", "hello"),
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8": ("SHA256", "password"),
        }
        self.common_inputs = [
            "", "test", "password", "hello", "world", "foo", "bar", "secret", "crypt", "key",
            "admin", "login", "user", "123456", "qwerty", "abc123", "letmein", "welcome",
            "سلام", "جهان", "مرحبا", "رمزنگاری", "پارسی", "عربي"
        ]
        self.common_keys = {
            "Vigenere": ["key", "secret", "password", "code", "crypt", "secure", "test", "hello", "world", "data"],
            "Substitution": ["zyxwvutsrqponmlkjihgfedcba", "qwertyuiopasdfghjklzxcvbnm", "abcdefghijklmnopqrstuvwxyz"],
            "Playfair": ["keyword", "secret", "playfair", "crypto", "test", "code", "secure", "data"],
        }
        self.common_shifts = list(range(1, 26))
        self.common_ab_keys = [(1, 1), (5, 3), (7, 5), (11, 7), (13, 9), (17, 11), (19, 13), (23, 15)]
        self.common_rails = [2, 3, 4, 5, 6, 7, 8]
        self.classifier = self.train_classifier()
        self.max_attempts = 10000
        self.timeout_seconds = 20
        self.gpu_available = cuda.is_available()

    def init_ui(self):
        main_layout = QVBoxLayout()
        self.setLayout(main_layout)
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        scroll_area.setWidget(scroll_widget)
        main_layout.addWidget(scroll_area)

        input_layout = QVBoxLayout()
        self.enter_text_label = QLabel(self.get_string("enter_text_smart_decrypt", "Enter text to decrypt"))
        self.enter_text_label.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        self.input_entry = QTextEdit()
        self.input_entry.setFixedHeight(100)
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(10)
        shadow.setColor(QColor(0, 0, 0, 50))
        self.input_entry.setGraphicsEffect(shadow)
        input_layout.addWidget(self.enter_text_label)
        input_layout.addWidget(self.input_entry)

        self.method_selector = QComboBox()
        self.method_selector.addItems([
            self.get_string("all_methods", "All Methods"),
            self.get_string("classical_ciphers", "Classical Ciphers"),
            self.get_string("modern_ciphers", "Modern Ciphers"),
            self.get_string("hash_methods", "Hash Cracking")
        ])
        self.method_selector.setFont(QFont("Segoe UI", 12))
        input_layout.addWidget(QLabel(self.get_string("select_method_label", "Select decryption methods")))
        input_layout.addWidget(self.method_selector)

        scroll_layout.addLayout(input_layout)

        button_layout = QHBoxLayout()
        self.decrypt_button = QPushButton(self.get_string("decrypt_button_level5", "Smart Decrypt"))
        self.add_button_animation(self.decrypt_button)
        self.decrypt_button.clicked.connect(self.smart_decrypt)
        self.cancel_button = QPushButton(self.get_string("cancel_button", "Cancel"))
        self.add_button_animation(self.cancel_button)
        self.cancel_button.clicked.connect(self.cancel_decryption)
        self.cancel_button.setEnabled(False)
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
        button_layout.addWidget(self.decrypt_button)
        button_layout.addWidget(self.cancel_button)
        button_layout.addWidget(self.clear_button)
        button_layout.addWidget(self.copy_input_button)
        button_layout.addWidget(self.paste_button)
        button_layout.addWidget(self.copy_output_button)
        scroll_layout.addLayout(button_layout)

        result_layout = QVBoxLayout()
        self.result_label = QLabel(self.get_string("result_label", "Result"))
        self.result_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        self.result_text = QTextEdit()
        self.result_text.setFixedHeight(200)
        self.result_text.setReadOnly(True)
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(10)
        shadow.setColor(QColor(0, 0, 0, 50))
        self.result_text.setGraphicsEffect(shadow)
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        result_layout.addWidget(self.result_label)
        result_layout.addWidget(self.result_text)
        result_layout.addWidget(self.progress_bar)
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

    def calculate_entropy(self, text):
        if not text:
            return 0
        freq = Counter(text)
        length = len(text)
        entropy = -sum((count / length) * math.log2(count / length) for count in freq.values() if count > 0)
        return entropy

    def extract_features(self, text):
        try:
            words = re.findall(r'\w+', text)
            avg_word_len = sum(len(word) for word in words) / len(words) if words else 0
            char_freq = Counter(text.lower())
            total_chars = sum(char_freq.values())
            lang_freq = self.persian_freq if self.current_language == "Persian" else self.arabic_freq if self.current_language == "Arabic" else self.english_freq
            freq_score = sum((char_freq.get(c, 0) / total_chars - lang_freq.get(c, 0)) ** 2 for c in lang_freq) if total_chars > 0 else 0
            features = {
                "length": len(text),
                "entropy": self.calculate_entropy(text),
                "alpha_ratio": sum(c.isalpha() for c in text) / len(text) if text else 0,
                "digit_ratio": sum(c.isdigit() for c in text) / len(text) if text else 0,
                "special_ratio": sum(c in "+/=" for c in text) / len(text) if text else 0,
                "hex_pattern": 1 if bool(re.match(r'^[0-9a-fA-F]+$', text.strip())) else 0,
                "base64_pattern": 1 if bool(re.match(r'^[A-Za-z0-9+/=]+$', text.strip())) else 0,
                "morse_pattern": 1 if bool(re.match(r'^[.-/\s]+$', text.strip())) else 0,
                "binary_pattern": 1 if bool(re.match(r'^[01\s]+$', text.strip())) else 0,
                "avg_word_length": avg_word_len,
                "freq_score": freq_score,
            }
            return list(features.values())
        except Exception as e:
            self.result_text.append(f"Error extracting features: {str(e)}")
            return [0] * 11

    def calculate_bigram_score(self, text):
        try:
            text = text.lower()
            bigrams = [text[i:i+2] for i in range(len(text)-1) if all(c.isalpha() or c in self.persian_freq or c in self.arabic_freq for c in text[i:i+2])]
            if not bigrams:
                return 0
            common_bigrams = {
                "English": {'th': 0.035, 'he': 0.030, 'in': 0.023, 'er': 0.020, 'an': 0.017, 're': 0.015, 'nd': 0.015},
                "Persian": {'را': 0.04, 'ای': 0.03, 'ان': 0.03, 'در': 0.02, 'با': 0.02, 'ست': 0.02, 'ها': 0.02},
                "Arabic": {'ال': 0.05, 'في': 0.03, 'من': 0.03, 'عن': 0.02, 'با': 0.02, 'عل': 0.02, 'ها': 0.02}
            }
            lang_bigrams = common_bigrams.get(self.current_language, common_bigrams["English"])
            score = sum(lang_bigrams.get(bigram, 0) for bigram in bigrams) / len(bigrams)
            return score
        except:
            return 0

    def calculate_trigram_score(self, text):
        try:
            text = text.lower()
            trigrams = [text[i:i+3] for i in range(len(text)-2) if all(c.isalpha() or c in self.persian_freq or c in self.arabic_freq for c in text[i:i+3])]
            if not trigrams:
                return 0
            common_trigrams = {
                "English": {'the': 0.018, 'and': 0.015, 'ing': 0.012, 'ion': 0.010, 'ent': 0.008},
                "Persian": {'است': 0.02, 'های': 0.015, 'درا': 0.012, 'برای': 0.010, 'ملی': 0.008},
                "Arabic": {'في': 0.02, 'من': 0.015, 'على': 0.012, 'الت': 0.010, 'هذا': 0.008}
            }
            lang_trigrams = common_trigrams.get(self.current_language, common_trigrams["English"])
            score = sum(lang_trigrams.get(trigram, 0) for trigram in trigrams) / len(trigrams)
            return score
        except:
            return 0

    def train_classifier(self):
        try:
            X = []
            y = []
            sample_texts = [
                "Hello World", "Test", "Sample Text", "سلام", "مرحبا",
                "رمزنگاری", "جهان", "سلام دنیا", "مرحبا بالعالم", "Cryptography",
                "password", "secret", "key", "foo", "bar", "admin", "login"
            ]
            for text in sample_texts:
                for _ in range(50):
                    try:
                        encoded = self.crypto_utils.base64_encode_text(text)
                        X.append(self.extract_features(encoded))
                        y.append("Base64")
                    except:
                        continue
                    try:
                        encoded = self.crypto_utils.hex_encode_text(text)
                        X.append(self.extract_features(encoded))
                        y.append("Hex")
                    except:
                        continue
                    try:
                        morse = self.crypto_utils.morse_encode_text(text)
                        X.append(self.extract_features(morse))
                        y.append("Morse")
                    except:
                        continue
                    try:
                        binary = self.crypto_utils.binary_encode_text(text)
                        X.append(self.extract_features(binary))
                        y.append("Binary")
                    except:
                        continue
                    try:
                        encoded = self.crypto_utils.base32_encode_text(text)
                        X.append(self.extract_features(encoded))
                        y.append("Base32")
                    except:
                        continue
                    for shift in range(1, 10):
                        try:
                            encoded = self.crypto_utils.caesar_cipher_encrypt(text, shift)
                            X.append(self.extract_features(encoded))
                            y.append("Caesar")
                        except:
                            continue
                    for key in self.common_keys["Vigenere"][:3]:
                        try:
                            encoded = self.crypto_utils.vigenere_cipher_encrypt(text, key)
                            X.append(self.extract_features(encoded))
                            y.append("Vigenere")
                        except:
                            continue
                    try:
                        encoded = self.crypto_utils.atbash_cipher_encrypt(text)
                        X.append(self.extract_features(encoded))
                        y.append("Atbash")
                    except:
                        continue
                    try:
                        encoded = self.crypto_utils.reverse_string(text)
                        X.append(self.extract_features(encoded))
                        y.append("Reverse String")
                    except:
                        continue
                    for rails in [2, 3, 4]:
                        try:
                            encoded = self.crypto_utils.rail_fence_encrypt(text, rails)
                            X.append(self.extract_features(encoded))
                            y.append("Rail Fence")
                        except:
                            continue
            clf = GaussianNB()
            clf.fit(X, y)
            return clf
        except Exception as e:
            self.result_text.append(f"Error training classifier: {str(e)}")
            return GaussianNB()

    def detect_algorithm(self, text):
        try:
            features = self.extract_features(text)
            probabilities = self.classifier.predict_proba([features])[0]
            labels = self.classifier.classes_
            return sorted(zip(labels, probabilities), key=lambda x: x[1], reverse=True)[:3]
        except Exception as e:
            self.result_text.append(f"Error in algorithm detection: {str(e)}")
            return [("Base64", 0.5), ("Hex", 0.3), ("Caesar", 0.2)]

    def is_readable(self, text):
        try:
            if not text:
                return False, 0
            text = unicodedata.normalize('NFKD', text)
            text.encode('utf-8').decode('utf-8')
            printable = sum(c in string.printable or c in self.persian_freq or c in self.arabic_freq for c in text)
            readable_score = printable / len(text) if len(text) > 0 else 0
            if readable_score < 0.3:
                return False, readable_score
            freq = Counter(c for c in text.lower() if c.isalpha() or c in self.persian_freq or c in self.arabic_freq)
            total = sum(freq.values())
            if total == 0:
                return True, readable_score
            lang_freq = self.persian_freq if self.current_language == "Persian" else self.arabic_freq if self.current_language == "Arabic" else self.english_freq
            chi_square = sum(((freq.get(c, 0) / total - lang_freq.get(c, 0)) ** 2) / lang_freq.get(c, 0.001) for c in lang_freq)
            freq_score = 1 / (1 + chi_square)
            bigram_score = self.calculate_bigram_score(text)
            trigram_score = self.calculate_trigram_score(text)
            final_score = readable_score * 0.4 + freq_score * 0.3 + bigram_score * 0.2 + trigram_score * 0.1
            return True, final_score
        except UnicodeError:
            return False, 0
        except Exception as e:
            self.result_text.append(f"Error checking readability: {str(e)}")
            return False, 0

    def kasiski_vigenere(self, text):
        try:
            def find_repeated_sequences(text, min_len=3, max_len=8):
                sequences = {}
                for length in range(min_len, max_len + 1):
                    for i in range(len(text) - length):
                        seq = text[i:i + length]
                        if seq in sequences:
                            sequences[seq].append(i)
                        else:
                            sequences[seq] = [i]
                distances = []
                for seq, positions in sequences.items():
                    if len(positions) > 1:
                        for i in range(1, len(positions)):
                            distances.append(positions[i] - positions[i-1])
                return distances

            def gcd(a, b):
                while b:
                    a, b = b, a % b
                return a

            distances = find_repeated_sequences(text)
            if not distances:
                return 3
            key_length = distances[0]
            for d in distances[1:]:
                key_length = gcd(key_length, d)
            return max(2, min(key_length, 10))
        except:
            return 3

    def is_potential_hash(self, text):
        try:
            text = text.strip().lower()
            if not re.match(r'^[0-9a-f]+$', text):
                return None
            text_length = len(text)
            for algo, (length, _) in self.hash_algorithms.items():
                if text_length == length:
                    return algo
            return None
        except:
            return None

    def is_potential_base64(self, text):
        try:
            text = text.strip()
            if not re.match(r'^[A-Za-z0-9+/=]+$', text):
                return False
            if len(text) % 4 != 0:
                text += '=' * (4 - len(text) % 4)
            base64.b64decode(text, validate=True)
            return True
        except:
            return False

    def is_potential_hex(self, text):
        try:
            return bool(re.match(r'^[0-9a-fA-F]+$', text.strip()))
        except:
            return False

    def is_potential_morse(self, text):
        try:
            return bool(re.match(r'^[.-/\s]+$', text.strip()))
        except:
            return False

    def is_potential_binary(self, text):
        try:
            return bool(re.match(r'^[01\s]+$', text.strip()))
        except:
            return False

    def is_potential_polybius(self, text):
        try:
            return bool(re.match(r'^\d+$', text.strip()))
        except:
            return False

    @numba.jit(nopython=True)
    def md5_hash_cpu(self, input_bytes):
        return hashlib.md5(input_bytes).hexdigest()

    def sha1_hash_cpu(self, input_bytes):
        return hashlib.sha1(input_bytes).hexdigest()

    def sha256_hash_cpu(self, input_bytes):
        return hashlib.sha256(input_bytes).hexdigest()

    def sha512_hash_cpu(self, input_bytes):
        return hashlib.sha512(input_bytes).hexdigest()

    def try_unhash(self, hash_value, max_attempts=10000):
        try:
            hash_value = hash_value.lower()
            if hash_value in self.hash_dictionary:
                algo, original = self.hash_dictionary[hash_value]
                return algo, original

            with ThreadPoolExecutor(max_workers=multiprocessing.cpu_count()) as executor:
                futures = []
                for algo, (length, hash_func) in self.hash_algorithms.items():
                    if len(hash_value) != length:
                        continue
                    futures.append(executor.submit(self.try_unhash_worker, hash_value, algo, hash_func, self.common_inputs))
                for future in as_completed(futures):
                    if self.is_cancelled:
                        return None, None
                    try:
                        algo, original = future.result()
                        if original:
                            return algo, original
                    except Exception as e:
                        self.result_text.append(self.get_string("hash_cracking_error", f"Error cracking {algo} hash: {str(e)}"))

                dictionary = self.common_inputs + [''.join(c) for c in itertools.product(string.ascii_lowercase, repeat=4)]
                dictionary.extend([str(i) for i in range(1000)])
                attempts = 0
                batch_size = 500
                while attempts < max_attempts:
                    if self.is_cancelled:
                        return None, None
                    candidates = [random.choice(dictionary) + ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(0, 6))) for _ in range(batch_size)]
                    for algo, (length, hash_func) in self.hash_algorithms.items():
                        if len(hash_value) != length:
                            continue
                        futures.append(executor.submit(self.try_unhash_worker, hash_value, algo, hash_func, candidates))
                    for future in as_completed(futures):
                        if self.is_cancelled:
                            return None, None
                        try:
                            algo, original = future.result()
                            if original:
                                return algo, original
                        except Exception as e:
                            self.result_text.append(self.get_string("hash_cracking_error", f"Error cracking {algo} hash: {str(e)}"))
                    attempts += batch_size
                    self.progress_bar.setValue(int((attempts / max_attempts) * 100))
                    QApplication.processEvents()
                return None, None
        except Exception as e:
            self.result_text.append(self.get_string("hash_cracking_error", f"Error cracking hash: {str(e)}"))
            return None, None

    def try_unhash_worker(self, hash_value, algo, hash_func, inputs):
        try:
            for input_text in inputs:
                computed_hash = hash_func(input_text.encode('utf-8')).lower()
                if computed_hash == hash_value:
                    return algo, input_text
            return None, None
        except:
            return None, None

    def try_key_recovery(self, text, algo, key_type):
        try:
            if algo == "RSA":
                return None, self.get_string("key_recovery_rsa_message", "RSA decryption requires the private key, not feasible in this version.")
            elif algo in ["AES", "Blowfish", "ChaCha20", "TripleDES"]:
                return None, self.get_string("key_recovery_symmetric_message", f"Brute-forcing {algo} key is not supported.")
            elif algo == "Caesar":
                best_shift, best_score = None, 0
                for shift in self.common_shifts:
                    if self.is_cancelled:
                        return None, self.get_string("decryption_cancelled", "Decryption process cancelled.")
                    cache_key = (algo, shift, text)
                    if cache_key in self.cache:
                        result = self.cache[cache_key]
                    else:
                        result = self.crypto_utils.caesar_cipher_decrypt(text, shift)
                        self.cache[cache_key] = result
                    readable, score = self.is_readable(result)
                    if readable and score > best_score:
                        best_shift, best_score = shift, score
                if best_shift is not None:
                    return best_shift, None
                return None, self.get_string("key_recovery_cipher_message", f"Failed to recover key for {algo}: Invalid input format.")
            elif algo == "Vigenere":
                key_length = self.kasiski_vigenere(text)
                best_key, best_score = None, 0
                for key in self.common_keys.get("Vigenere", []):
                    if self.is_cancelled:
                        return None, self.get_string("decryption_cancelled", "Decryption process cancelled.")
                    cache_key = (algo, key, text)
                    if cache_key in self.cache:
                        result = self.cache[cache_key]
                    else:
                        result = self.crypto_utils.vigenere_cipher_decrypt(text, key)
                        self.cache[cache_key] = result
                    readable, score = self.is_readable(result)
                    if readable and score > best_score:
                        best_key, best_score = key, score
                if best_key is None and len(text) > 10:
                    try:
                        blocks = [[] for _ in range(key_length)]
                        for i, char in enumerate(text.lower()):
                            if char.isalpha():
                                blocks[i % key_length].append(char)
                        key = ""
                        lang_freq = self.persian_freq if self.current_language == "Persian" else self.arabic_freq if self.current_language == "Arabic" else self.english_freq
                        for block in blocks:
                            if not block:
                                continue
                            block_freq = Counter(block)
                            total = sum(block_freq.values())
                            chi_squares = []
                            for shift in range(26):
                                shifted_freq = {chr((ord(c) - ord('a') - shift) % 26 + ord('a')): count/total for c, count in block_freq.items() if c.isalpha()}
                                chi_square = sum(((shifted_freq.get(c, 0) - lang_freq.get(c, 0)) ** 2) / lang_freq.get(c, 0.001) for c in lang_freq)
                                chi_squares.append((shift, chi_square))
                            best_shift = min(chi_squares, key=lambda x: x[1])[0]
                            key += chr(best_shift + ord('a'))
                        if key:
                            cache_key = (algo, key, text)
                            if cache_key in self.cache:
                                result = self.cache[cache_key]
                            else:
                                result = self.crypto_utils.vigenere_cipher_decrypt(text, key)
                                self.cache[cache_key] = result
                            readable, score = self.is_readable(result)
                            if readable and score > best_score:
                                best_key, best_score = key, score
                    except:
                        pass
                if best_key is not None:
                    return best_key, None
                return None, self.get_string("key_recovery_cipher_message", f"Failed to recover key for {algo}: Invalid input format.")
            elif algo == "Affine":
                best_keys, best_score = None, 0
                for a, b in self.common_ab_keys:
                    if self.is_cancelled:
                        return None, self.get_string("decryption_cancelled", "Decryption process cancelled.")
                    cache_key = (algo, (a, b), text)
                    if cache_key in self.cache:
                        result = self.cache[cache_key]
                    else:
                        result = self.crypto_utils.affine_cipher_decrypt(text, a, b)
                        self.cache[cache_key] = result
                    readable, score = self.is_readable(result)
                    if readable and score > best_score:
                        best_keys, best_score = (a, b), score
                if best_keys is not None:
                    return best_keys, None
                return None, self.get_string("key_recovery_cipher_message", f"Failed to recover key for {algo}: Invalid input format.")
            elif algo == "Rail Fence":
                best_rails, best_score = None, 0
                for rails in self.common_rails:
                    if self.is_cancelled:
                        return None, self.get_string("decryption_cancelled", "Decryption process cancelled.")
                    cache_key = (algo, rails, text)
                    if cache_key in self.cache:
                        result = self.cache[cache_key]
                    else:
                        result = self.crypto_utils.rail_fence_decrypt(text, rails)
                        self.cache[cache_key] = result
                    readable, score = self.is_readable(result)
                    if readable and score > best_score:
                        best_rails, best_score = rails, score
                if best_rails is not None:
                    return best_rails, None
                return None, self.get_string("key_recovery_cipher_message", f"Failed to recover key for {algo}: Invalid input format.")
            elif algo == "Substitution":
                best_key, best_score = None, 0
                for key in self.common_keys.get("Substitution", [])[:2]:
                    if self.is_cancelled:
                        return None, self.get_string("decryption_cancelled", "Decryption process cancelled.")
                    cache_key = (algo, key, text)
                    if cache_key in self.cache:
                        result = self.cache[cache_key]
                    else:
                        result = self.crypto_utils.simple_substitution_decrypt(text, key)
                        self.cache[cache_key] = result
                    readable, score = self.is_readable(result)
                    if readable and score > best_score:
                        best_key, best_score = key, score
                if best_key is not None:
                    return best_key, None
                return None, self.get_string("key_recovery_cipher_message", f"Failed to recover key for {algo}: Invalid input format.")
            elif algo == "Playfair":
                best_key, best_score = None, 0
                for key in self.common_keys.get("Playfair", [])[:2]:
                    if self.is_cancelled:
                        return None, self.get_string("decryption_cancelled", "Decryption process cancelled.")
                    cache_key = (algo, key, text)
                    if cache_key in self.cache:
                        result = self.cache[cache_key]
                    else:
                        result = self.crypto_utils.playfair_decrypt(text, key)
                        self.cache[cache_key] = result
                    readable, score = self.is_readable(result)
                    if readable and score > best_score:
                        best_key, best_score = key, score
                if best_key is not None:
                    return best_key, None
                return None, self.get_string("key_recovery_cipher_message", f"Failed to recover key for {algo}: Invalid input format.")
            return None, self.get_string("key_recovery_failed", f"Failed to recover key for {algo}: Method not supported.")
        except Exception as e:
            return None, self.get_string("key_recovery_failed", f"Failed to recover key for {algo}: {str(e)}")

    def try_multi_layer_decoding(self, text, max_layers=3):
        try:
            candidates = [(text, [], 0)]
            tried_methods = set()
            start_time = time.time()
            for layer in range(max_layers):
                if self.is_cancelled:
                    return self.get_string("decryption_cancelled", "Decryption process cancelled.")
                new_candidates = []
                methods_to_try = [(name, method, key_type) for name, method, key_type in self.decoding_methods + self.cipher_methods if name not in tried_methods]
                total_steps = len(methods_to_try)
                step = 0
                with ThreadPoolExecutor(max_workers=multiprocessing.cpu_count()) as executor:
                    futures = []
                    for current_text, used_methods, base_score in candidates:
                        for method_name, method, key_type in methods_to_try:
                            if time.time() - start_time > self.timeout_seconds:
                                return self.get_string("processing_timeout", f"Processing timeout for multi-layer decoding. Try a smaller input or fewer methods.")
                            step += 1
                            self.progress_bar.setValue(int((step / total_steps) * 100))
                            self.result_text.setPlainText(self.get_string("progress_message", f"Processing {step} of {total_steps} methods..."))
                            QApplication.processEvents()
                            futures.append(executor.submit(self.try_decoding_method, method_name, method, key_type, current_text))
                    for future in as_completed(futures):
                        if self.is_cancelled:
                            return self.get_string("decryption_cancelled", "Decryption process cancelled.")
                        try:
                            result = future.result()
                            if isinstance(result, tuple):
                                new_candidates.append((result[0], used_methods + [result[2]], base_score + result[1]))
                            elif isinstance(result, str):
                                self.result_text.append(result)
                        except Exception as e:
                            self.result_text.append(f"Error in multi-layer decoding: {str(e)}")
                        tried_methods.update([m[0] for m in methods_to_try])
                        candidates.extend(new_candidates)
                if not new_candidates:
                    break
            if candidates:
                best_candidate, best_methods, best_score = max(candidates, key=lambda x: x[2])
                return self.get_string("multi_layer_detected", f"Multi-layer decryption: Methods: {', '.join(best_methods)}\nScore: {best_score:.3f}\nResult: {best_candidate}")
            return None
        except Exception as e:
            self.result_text.append(f"Error in multi-layer decoding: {str(e)}")
            return None

    def try_decoding_method(self, method_name, method, key_type, text):
        try:
            cache_key = (method_name, text, key_type)
            if cache_key in self.cache:
                result = self.cache[cache_key]
                if isinstance(result, tuple) and result[0]:
                    return result
                return None

            if method_name == "Base64":
                if not self.is_potential_base64(text):
                    return None
                try:
                    result = method(text)
                    readable, score = self.is_readable(result)
                    if readable:
                        self.cache[cache_key] = (result, score, method_name)
                        return result, score, method_name
                    return None
                except Exception as e:
                    return self.get_string("base64_decode_error", f"Failed to decode Base64: Invalid format.")
            elif method_name in ["Hex", "Morse", "Binary", "Polybius"]:
                if (method_name == "Hex" and not self.is_potential_hex(text)) or \
                   (method_name == "Morse" and not self.is_potential_morse(text)) or \
                   (method_name == "Binary" and not self.is_potential_binary(text)) or \
                   (method_name == "Polybius" and not self.is_potential_polybius(text)):
                    return None
                try:
                    result = method(text)
                    readable, score = self.is_readable(result)
                    if readable:
                        self.cache[cache_key] = (result, score, method_name)
                        return result, score, method_name
                    return None
                except Exception as e:
                    return self.get_string("invalid_input_format", f"Invalid input format for {method_name}: {str(e)}")
            elif key_type is None:
                try:
                    result = method(text)
                    readable, score = self.is_readable(result)
                    if readable:
                        self.cache[cache_key] = (result, score, method_name)
                        return result, score, method_name
                    return None
                except Exception as e:
                    return self.get_string("invalid_input_format", f"Invalid input format for {method_name}: {str(e)}")
            else:
                key, message = self.try_key_recovery(text, method_name, key_type)
                if key:
                    try:
                        if key_type == "shift":
                            result = method(text, key)
                        elif key_type == "key":
                            result = method(text, key)
                        elif key_type == "ab_keys":
                            a, b = key
                            result = method(text, a, b)
                        elif key_type == "rails":
                            result = method(text, key)
                        readable, score = self.is_readable(result)
                        if readable:
                            self.cache[cache_key] = (result, score, f"{method_name} (key={key})")
                            return result, score, f"{method_name} (key={key})"
                        return None
                    except Exception as e:
                        return self.get_string("invalid_input_format", f"Invalid input format for {method_name}: {str(e)}")
                return None
        except Exception as e:
            return self.get_string("invalid_input_format", f"Invalid input format for {method_name}: {str(e)}")

    def smart_decrypt(self):
        text = self.input_entry.toPlainText().strip()
        if not text:
            QMessageBox.warning(self, self.get_string("algorithm_error_title", "Algorithm Error"),
                              self.get_string("clipboard_empty", "Input is empty"))
            return

        self.result_text.clear()
        self.progress_bar.setValue(0)
        self.is_cancelled = False
        self.cancel_button.setEnabled(True)

        selected_method = self.method_selector.currentText()
        methods_to_try = []
        if selected_method == self.get_string("all_methods", "All Methods"):
            methods_to_try = self.decoding_methods + self.cipher_methods
        elif selected_method == self.get_string("classical_ciphers", "Classical Ciphers"):
            methods_to_try = self.cipher_methods
        elif selected_method == self.get_string("modern_ciphers", "Modern Ciphers"):
            methods_to_try = self.encryption_methods
        elif selected_method == self.get_string("hash_methods", "Hash Cracking"):
            methods_to_try = []
        else:
            QMessageBox.warning(self, self.get_string("algorithm_error_title", "Algorithm Error"),
                              self.get_string("no_methods_selected", "No methods selected for decryption."))
            return

        # Prioritize Base64 if detected
        if self.is_potential_base64(text):
            try:
                result, score, method_name = self.try_decoding_method("Base64", self.crypto_utils.base64_decode_text, None, text)
                if result and score > 0:
                    self.progress_bar.setValue(100)
                    self.cancel_button.setEnabled(False)
                    output_text = (
                        f"{self.get_string('result_number', 'Best Result:')}\n"
                        f"{self.get_string('algorithm_used', 'Algorithm: {0}').format(method_name)}\n"
                        f"{self.get_string('readability_score', 'Readability Score: {0}').format(f'{score:.3f}')}\n"
                        f"{result}"
                    )
                    self.result_text.setPlainText(output_text)
                    return
                else:
                    self.result_text.append(self.get_string("base64_decode_error", "Failed to decode Base64: Invalid format."))
            except Exception as e:
                self.result_text.append(self.get_string("base64_decode_error", f"Failed to decode Base64: {str(e)}"))

        hash_algo = self.is_potential_hash(text)
        if hash_algo and (selected_method == self.get_string("hash_methods", "Hash Cracking") or
                         selected_method == self.get_string("all_methods", "All Methods")):
            confirm = QMessageBox.question(
                self,
                self.get_string("hash_detected_title", "Hash Detected"),
                self.get_string("hash_detected_message", f"The input appears to be a {hash_algo} hash. Attempt to crack it using a dictionary or up to 10,000 random attempts?"),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if confirm == QMessageBox.StandardButton.Yes:
                try:
                    self.progress_bar.setValue(0)
                    algo, original = self.try_unhash(text)
                    self.progress_bar.setValue(100)
                    self.cancel_button.setEnabled(False)
                    if original:
                        output_text = (
                            f"{self.get_string('result_number', 'Best Result:')}\n"
                            f"{self.get_string('algorithm_used', 'Algorithm: {0}').format(algo)}\n"
                            f"{self.get_string('hash_cracked_message', 'Hash {0} cracked: {1}').format(algo, original)}"
                        )
                        self.result_text.setPlainText(output_text)
                    else:
                        self.result_text.setPlainText(
                            f"{self.get_string('hash_cracking_failed', 'Failed to crack {0} hash: No match found after {1} attempts.').format(hash_algo, self.max_attempts)}"
                        )
                    return
                except Exception as e:
                    self.progress_bar.setValue(100)
                    self.cancel_button.setEnabled(False)
                    self.result_text.setPlainText(
                        f"{self.get_string('hash_cracking_error', 'Error cracking {0} hash: {1}').format(hash_algo, str(e))}"
                    )
                    return

        if selected_method != self.get_string("hash_methods", "Hash Cracking"):
            self.result_text.setPlainText(self.get_string("testing_algorithms", "Testing algorithms from Ciphers and Encoders/Decoders..."))
            QApplication.processEvents()

            candidates = []
            total_steps = sum(1 for m in methods_to_try) + sum(len(self.common_shifts) if m[0] == "Caesar" else len(self.common_keys.get(m[0], [])) if m[0] in ["Vigenere", "Substitution", "Playfair"] else len(self.common_ab_keys) if m[0] == "Affine" else len(self.common_rails) if m[0] == "Rail Fence" else 1 for m in methods_to_try)
            step = 0
            start_time = time.time()

            with ThreadPoolExecutor(max_workers=multiprocessing.cpu_count()) as executor:
                futures = []
                for method_name, method, key_type in methods_to_try:
                    if self.is_cancelled:
                        self.result_text.setPlainText(self.get_string("decryption_cancelled", "Decryption process cancelled."))
                        self.progress_bar.setValue(100)
                        self.cancel_button.setEnabled(False)
                        return
                    if time.time() - start_time > self.timeout_seconds:
                        self.result_text.setPlainText(
                            f"{self.get_string('processing_timeout', 'Processing timeout for {0}. Try a smaller input or fewer methods.').format(method_name)}"
                        )
                        self.progress_bar.setValue(100)
                        self.cancel_button.setEnabled(False)
                        return
                    futures.append(executor.submit(self.try_decoding_method, method_name, method, key_type, text))

                for future in as_completed(futures):
                    if self.is_cancelled:
                        self.result_text.setPlainText(self.get_string("decryption_cancelled", "Decryption process cancelled."))
                        self.progress_bar.setValue(100)
                        self.cancel_button.setEnabled(False)
                        return
                    if time.time() - start_time > self.timeout_seconds:
                        self.result_text.setPlainText(
                            f"{self.get_string('processing_timeout', 'Processing timeout for decoding. Try a smaller input or fewer methods.')}"
                        )
                        self.progress_bar.setValue(100)
                        self.cancel_button.setEnabled(False)
                        return
                    step += 1
                    self.progress_bar.setValue(int((step / total_steps) * 100))
                    self.result_text.setPlainText(self.get_string("progress_message", f"Processing {step} of {total_steps} methods..."))
                    QApplication.processEvents()
                    try:
                        result = future.result()
                        if isinstance(result, tuple):
                            candidates.append(result)
                        elif isinstance(result, str):
                            self.result_text.append(result)
                    except Exception as e:
                        self.result_text.append(f"Error in decoding method: {str(e)}")

            if candidates:
                best_candidate, best_score, best_method = max(candidates, key=lambda x: x[1])
                self.progress_bar.setValue(100)
                self.cancel_button.setEnabled(False)
                self.result_text.clear()
                output_text = (
                    f"{self.get_string('result_number', 'Best Result:')}\n"
                    f"{self.get_string('algorithm_used', 'Algorithm: {0}').format(best_method)}\n"
                    f"{self.get_string('readability_score', 'Readability Score: {0}').format(f'{best_score:.3f}')}\n"
                    f"{best_candidate}"
                )
                self.result_text.setPlainText(output_text)
            else:
                multi_layer_result = self.try_multi_layer_decoding(text)
                self.progress_bar.setValue(100)
                self.cancel_button.setEnabled(False)
                if multi_layer_result:
                    self.result_text.setPlainText(multi_layer_result)
                else:
                    self.result_text.setPlainText(
                        f"{self.get_string('no_readable_results', 'No readable results found. Try a different input.')}"
                    )

    def cancel_decryption(self):
        self.is_cancelled = True
        self.result_text.setPlainText(self.get_string("decryption_cancelled", "Decryption process cancelled."))
        self.progress_bar.setValue(100)
        self.cancel_button.setEnabled(False)

    def clear_text(self):
        self.input_entry.clear()
        self.result_text.clear()
        self.progress_bar.setValue(0)
        self.is_cancelled = False
        self.cancel_button.setEnabled(False)
        self.cache.clear()

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
        self.enter_text_label.setText(self.get_string("enter_text_smart_decrypt", "Enter text to decrypt"))
        self.decrypt_button.setText(self.get_string("decrypt_button_level5", "Smart Decrypt"))
        self.cancel_button.setText(self.get_string("cancel_button", "Cancel"))
        self.clear_button.setText(self.get_string("clear_button", "Clear"))
        self.copy_input_button.setText(self.get_string("copy_input_button", "Copy Input"))
        self.paste_button.setText(self.get_string("paste_button", "Paste"))
        self.copy_output_button.setText(self.get_string("copy_output_button", "Copy Output"))
        self.result_label.setText(self.get_string("result_label", "Result"))
        self.method_selector.clear()
        self.method_selector.addItems([
            self.get_string("all_methods", "All Methods"),
            self.get_string("classical_ciphers", "Classical Ciphers"),
            self.get_string("modern_ciphers", "Modern Ciphers"),
            self.get_string("hash_methods", "Hash Cracking")
        ])