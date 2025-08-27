import base64
import urllib.parse
import codecs
import secrets
import hashlib
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import os
import mimetypes
import binascii
import string
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
import blowfish

try:
    from Crypto.Hash import Whirlpool
except ImportError:
    Whirlpool = None

class CryptoUtils:
    def __init__(self, language="English", strings=None):
        self.language = language
        self.strings = strings or {}

    def get_error_message(self, key):
        return self.strings.get(self.language, {}).get(key, f"Error: {key}")

    @staticmethod
    def caesar_cipher_encrypt(text, shift):
        result = ''
        for char in text:
            char_code = ord(char)
            encrypted_code = (char_code + shift) % 1114111
            result += chr(encrypted_code)
        return result

    @staticmethod
    def caesar_cipher_decrypt(text, shift):
        return CryptoUtils.caesar_cipher_encrypt(text, -shift)

    @staticmethod
    def vigenere_cipher_encrypt(text, key):
        result = ''
        key = key.strip()
        if not key:
            raise ValueError("vigenere_key_empty_error")
        key_length = len(key)
        key_index = 0
        for char in text:
            shift = ord(key[key_index % key_length]) % 1114111
            char_code = ord(char)
            encrypted_code = (char_code + shift) % 1114111
            result += chr(encrypted_code)
            key_index += 1
        return result

    @staticmethod
    def vigenere_cipher_decrypt(text, key):
        result = ''
        key = key.strip()
        if not key:
            raise ValueError("vigenere_key_empty_error")
        key_length = len(key)
        key_index = 0
        for char in text:
            shift = ord(key[key_index % key_length]) % 1114111
            char_code = ord(char)
            decrypted_code = (char_code - shift) % 1114111
            result += chr(decrypted_code)
            key_index += 1
        return result

    @staticmethod
    def affine_cipher_encrypt(text, a, b):
        result = ''
        a_key = int(a)
        b_key = int(b)
        if CryptoUtils.gcd(a_key, 1114111) != 1:
            raise ValueError("affine_key_error")
        for char in text:
            char_code = ord(char)
            encrypted_code = (a_key * char_code + b_key) % 1114111
            result += chr(encrypted_code)
        return result

    @staticmethod
    def affine_cipher_decrypt(text, a, b):
        result = ''
        a_key = int(a)
        b_key = int(b)
        if CryptoUtils.gcd(a_key, 1114111) != 1:
            raise ValueError("affine_key_error")
        a_inverse = 0
        for i in range(1114111):
            if (a_key * i) % 1114111 == 1:
                a_inverse = i
                break
        for char in text:
            char_code = ord(char)
            decrypted_code = (a_inverse * (char_code - b_key)) % 1114111
            result += chr(decrypted_code)
        return result

    @staticmethod
    def atbash_cipher_encrypt(text):
        result = ''
        for char in text:
            result += chr(1114111 - ord(char))
        return result

    @staticmethod
    def atbash_cipher_decrypt(text):
        return CryptoUtils.atbash_cipher_encrypt(text)

    @staticmethod
    def reverse_string(text):
        return text[::-1]

    @staticmethod
    def rail_fence_encrypt(text, rails):
        if rails < 1:
            raise ValueError("rail_fence_rails_error")
        if not text:
            return ""
        rail = [''] * rails
        row, step = 0, 1
        for char in text:
            rail[row] += char
            if row == 0:
                step = 1
            elif row == rails - 1:
                step = -1
            row += step
        return ''.join(rail)

    @staticmethod
    def rail_fence_decrypt(text, rails):
        if rails < 1:
            raise ValueError("rail_fence_rails_error")
        if not text:
            return ""
        n = len(text)
        rail_lengths = [0] * rails
        row, step = 0, 1
        for _ in range(n):
            rail_lengths[row] += 1
            if row == 0:
                step = 1
            elif row == rails - 1:
                step = -1
            row += step
        rail = [''] * rails
        index = 0
        for i in range(rails):
            rail[i] = text[index:index + rail_lengths[i]]
            index += rail_lengths[i]
        result = []
        row, step = 0, 1
        pos = [0] * rails
        for _ in range(n):
            result.append(rail[row][pos[row]])
            pos[row] += 1
            if row == 0:
                step = 1
            elif row == rails - 1:
                step = -1
            row += step
        return ''.join(result)

    @staticmethod
    def simple_substitution_encrypt(text, key):
        if len(key) < 1:
            raise ValueError("substitution_key_empty_error")
        key_map = {chr(i): key[i % len(key)] for i in range(1114111)}
        return ''.join(key_map.get(char, char) for char in text)

    @staticmethod
    def simple_substitution_decrypt(text, key):
        if len(key) < 1:
            raise ValueError("substitution_key_empty_error")
        reverse_map = {key[i % len(key)]: chr(i) for i in range(1114111)}
        return ''.join(reverse_map.get(char, char) for char in text)

    @staticmethod
    def playfair_encrypt(text, key):
        if not key:
            raise ValueError("playfair_key_empty_error")
        key = ''.join(c.upper() for c in key if c.isalpha())
        if not key:
            raise ValueError("playfair_key_invalid_error")
        text = ''.join(c.upper() for c in text if c.isalpha())
        if not text:
            return ""
        matrix = CryptoUtils._create_playfair_matrix(key)
        text = CryptoUtils._prepare_playfair_text(text)
        result = []
        for i in range(0, len(text), 2):
            a, b = text[i], text[i + 1]
            row1, col1 = CryptoUtils._find_position(matrix, a)
            row2, col2 = CryptoUtils._find_position(matrix, b)
            if row1 == row2:
                result.append(matrix[row1][(col1 + 1) % 5])
                result.append(matrix[row2][(col2 + 1) % 5])
            elif col1 == col2:
                result.append(matrix[(row1 + 1) % 5][col1])
                result.append(matrix[(row2 + 1) % 5][col2])
            else:
                result.append(matrix[row1][col2])
                result.append(matrix[row2][col1])
        return ''.join(result)

    @staticmethod
    def playfair_decrypt(text, key):
        if not key:
            raise ValueError("playfair_key_empty_error")
        key = ''.join(c.upper() for c in key if c.isalpha())
        if not key:
            raise ValueError("playfair_key_invalid_error")
        text = ''.join(c.upper() for c in text if c.isalpha())
        if not text:
            return ""
        matrix = CryptoUtils._create_playfair_matrix(key)
        result = []
        for i in range(0, len(text), 2):
            a, b = text[i], text[i + 1]
            row1, col1 = CryptoUtils._find_position(matrix, a)
            row2, col2 = CryptoUtils._find_position(matrix, b)
            if row1 == row2:
                result.append(matrix[row1][(col1 - 1) % 5])
                result.append(matrix[row2][(col2 - 1) % 5])
            elif col1 == col2:
                result.append(matrix[(row1 - 1) % 5][col1])
                result.append(matrix[(row2 - 1) % 5][col2])
            else:
                result.append(matrix[row1][col2])
                result.append(matrix[row2][col1])
        return ''.join(result)

    @staticmethod
    def _create_playfair_matrix(key):
        key = key.replace('J', 'I')
        alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
        matrix = []
        seen = set()
        for char in key:
            if char not in seen and char in alphabet:
                matrix.append(char)
                seen.add(char)
        for char in alphabet:
            if char not in seen:
                matrix.append(char)
        return [matrix[i:i + 5] for i in range(0, 25, 5)]

    @staticmethod
    def _prepare_playfair_text(text):
        text = text.replace('J', 'I')
        result = []
        i = 0
        while i < len(text):
            result.append(text[i])
            if i + 1 < len(text):
                if text[i] == text[i + 1]:
                    result.append('X')
                else:
                    result.append(text[i + 1])
                    i += 1
            i += 1
        if len(result) % 2 != 0:
            result.append('X')
        return ''.join(result)

    @staticmethod
    def _find_position(matrix, char):
        for i in range(5):
            for j in range(5):
                if matrix[i][j] == char:
                    return i, j
        return None

    @staticmethod
    def polybius_encrypt(text):
        polybius_square = {
            'A': '11', 'B': '12', 'C': '13', 'D': '14', 'E': '15',
            'F': '21', 'G': '22', 'H': '23', 'I': '24', 'J': '24', 'K': '25',
            'L': '31', 'M': '32', 'N': '33', 'O': '34', 'P': '35',
            'Q': '41', 'R': '42', 'S': '43', 'T': '44', 'U': '45',
            'V': '51', 'W': '52', 'X': '53', 'Y': '54', 'Z': '55'
        }
        text = text.upper()
        result = []
        for char in text:
            if char.isalpha():
                result.append(polybius_square.get(char, '24'))
        return ' '.join(result)

    @staticmethod
    def polybius_decrypt(text):
        polybius_square = {
            '11': 'A', '12': 'B', '13': 'C', '14': 'D', '15': 'E',
            '21': 'F', '22': 'G', '23': 'H', '24': 'I', '25': 'K',
            '31': 'L', '32': 'M', '33': 'N', '34': 'O', '35': 'P',
            '41': 'Q', '42': 'R', '43': 'S', '44': 'T', '45': 'U',
            '51': 'V', '52': 'W', '53': 'X', '54': 'Y', '55': 'Z'
        }
        pairs = text.replace(' ', '')
        if len(pairs) % 2 != 0:
            raise ValueError("polybius_input_error")
        result = []
        for i in range(0, len(pairs), 2):
            pair = pairs[i:i + 2]
            result.append(polybius_square.get(pair, 'I'))
        return ''.join(result)

    @staticmethod
    def base64_encode_text(text):
        try:
            return base64.b64encode(text.encode('utf-8')).decode('utf-8')
        except Exception:
            raise ValueError("invalid_base64_input")

    @staticmethod
    def base64_decode_text(text):
        try:
            return base64.b64decode(text.encode('utf-8')).decode('utf-8')
        except Exception:
            raise ValueError("invalid_base64_input")

    @staticmethod
    def rot13_encode_text(text):
        return codecs.encode(text, 'rot_13')

    @staticmethod
    def rot13_decode_text(text):
        return CryptoUtils.rot13_encode_text(text)

    @staticmethod
    def url_encode_text(text):
        try:
            return urllib.parse.quote(text)
        except Exception:
            raise ValueError("invalid_url_input")

    @staticmethod
    def url_decode_text(text):
        try:
            return urllib.parse.unquote(text)
        except Exception:
            raise ValueError("invalid_url_input")

    @staticmethod
    def hex_encode_text(text):
        try:
            return text.encode('utf-8').hex()
        except Exception:
            raise ValueError("invalid_hex_input")

    @staticmethod
    def hex_decode_text(text):
        try:
            return bytes.fromhex(text).decode('utf-8')
        except Exception:
            raise ValueError("invalid_hex_input")

    @staticmethod
    def ascii_encode_text(text):
        try:
            return ' '.join(str(ord(char)) for char in text)
        except Exception:
            raise ValueError("invalid_ascii_input")

    @staticmethod
    def ascii_decode_text(text):
        try:
            numbers = text.split()
            return ''.join(chr(int(num)) for num in numbers if num.isdigit())
        except Exception:
            raise ValueError("invalid_ascii_input")

    @staticmethod
    def binary_encode_text(text):
        try:
            return ' '.join(format(ord(char), '08b') for char in text)
        except Exception:
            raise ValueError("invalid_binary_input")

    @staticmethod
    def binary_decode_text(text):
        try:
            binary_chars = text.split()
            return ''.join(chr(int(b, 2)) for b in binary_chars if all(c in '01' for c in b))
        except Exception:
            raise ValueError("invalid_binary_input")

    @staticmethod
    def morse_encode_text(text):
        morse_code_dict = {
            'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
            'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
            'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
            'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
            'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
            'Z': '--..', '0': '-----', '1': '.----', '2': '..---', '3': '...--',
            '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..',
            '9': '----.', ' ': '/'
        }
        try:
            text = text.upper()
            return ' '.join(morse_code_dict.get(char, '') for char in text if char in morse_code_dict)
        except Exception:
            raise ValueError("invalid_morse_input")

    @staticmethod
    def morse_decode_text(text):
        morse_code_dict = {v: k for k, v in {
            'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
            'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
            'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
            'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
            'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
            'Z': '--..', '0': '-----', '1': '.----', '2': '..---', '3': '...--',
            '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..',
            '9': '----.', ' ': '/'
        }.items()}
        try:
            codes = text.split()
            return ''.join(morse_code_dict.get(code, '') for code in codes)
        except Exception:
            raise ValueError("invalid_morse_input")

    @staticmethod
    def quoted_printable_encode_text(text):
        try:
            result = []
            for char in text:
                if char in string.printable and char.isascii() and char not in '=\n\r':
                    result.append(char)
                else:
                    result.append(f'={ord(char):02X}')
            return ''.join(result)
        except Exception:
            raise ValueError("invalid_quoted_printable_input")

    @staticmethod
    def quoted_printable_decode_text(text):
        try:
            result = []
            i = 0
            while i < len(text):
                if text[i] == '=' and i + 2 < len(text):
                    hex_val = text[i+1:i+3]
                    result.append(chr(int(hex_val, 16)))
                    i += 3
                else:
                    result.append(text[i])
                    i += 1
            return ''.join(result)
        except Exception:
            raise ValueError("invalid_quoted_printable_input")

    @staticmethod
    def unicode_escape_encode_text(text):
        try:
            return ''.join(f'\\u{ord(char):04x}' for char in text)
        except Exception:
            raise ValueError("invalid_unicode_escape_input")

    @staticmethod
    def unicode_escape_decode_text(text):
        try:
            return text.encode().decode('unicode_escape')
        except Exception:
            raise ValueError("invalid_unicode_escape_input")

    @staticmethod
    def base32_encode_text(text):
        try:
            return base64.b32encode(text.encode('utf-8')).decode('utf-8')
        except Exception:
            raise ValueError("invalid_base32_input")

    @staticmethod
    def base32_decode_text(text):
        try:
            return base64.b32decode(text.encode('utf-8')).decode('utf-8')
        except Exception:
            raise ValueError("invalid_base32_input")

    @staticmethod
    def uuencode_text(text):
        try:
            return binascii.b2a_uu(text.encode('utf-8')).decode('utf-8')
        except Exception:
            raise ValueError("invalid_uuencode_input")

    @staticmethod
    def uudecode_text(text):
        try:
            return binascii.a2b_uu(text.encode('utf-8')).decode('utf-8')
        except Exception:
            raise ValueError("invalid_uuencode_input")

    @staticmethod
    def md5_hash_text(text):
        try:
            return hashlib.md5(text.encode('utf-8')).hexdigest()
        except Exception:
            raise ValueError("invalid_md5_input")

    @staticmethod
    def sha1_hash_text(text):
        try:
            return hashlib.sha1(text.encode('utf-8')).hexdigest()
        except Exception:
            raise ValueError("invalid_sha1_input")

    @staticmethod
    def sha224_hash_text(text):
        try:
            return hashlib.sha224(text.encode('utf-8')).hexdigest()
        except Exception:
            raise ValueError("invalid_sha224_input")

    @staticmethod
    def sha256_hash_text(text):
        try:
            return hashlib.sha256(text.encode('utf-8')).hexdigest()
        except Exception:
            raise ValueError("invalid_sha256_input")

    @staticmethod
    def sha384_hash_text(text):
        try:
            return hashlib.sha384(text.encode('utf-8')).hexdigest()
        except Exception:
            raise ValueError("invalid_sha384_input")

    @staticmethod
    def sha512_hash_text(text):
        try:
            return hashlib.sha512(text.encode('utf-8')).hexdigest()
        except Exception:
            raise ValueError("invalid_sha512_input")

    @staticmethod
    def sha3_224_hash_text(text):
        try:
            return hashlib.sha3_224(text.encode('utf-8')).hexdigest()
        except Exception:
            raise ValueError("invalid_sha3_224_input")

    @staticmethod
    def sha3_256_hash_text(text):
        try:
            return hashlib.sha3_256(text.encode('utf-8')).hexdigest()
        except Exception:
            raise ValueError("invalid_sha3_256_input")

    @staticmethod
    def sha3_384_hash_text(text):
        try:
            return hashlib.sha3_384(text.encode('utf-8')).hexdigest()
        except Exception:
            raise ValueError("invalid_sha3_384_input")

    @staticmethod
    def sha3_512_hash_text(text):
        try:
            return hashlib.sha3_512(text.encode('utf-8')).hexdigest()
        except Exception:
            raise ValueError("invalid_sha3_512_input")

    @staticmethod
    def ripemd160_hash_text(text):
        try:
            return hashlib.new('ripemd160', text.encode('utf-8')).hexdigest()
        except Exception:
            raise ValueError("invalid_ripemd160_input")

    @staticmethod
    def whirlpool_hash_text(text):
        if Whirlpool is None:
            raise ValueError("invalid_whirlpool_input")
        try:
            h = Whirlpool.new()
            h.update(text.encode('utf-8'))
            return h.hexdigest()
        except Exception:
            raise ValueError("invalid_whirlpool_input")

    @staticmethod
    def blake2b_hash_text(text):
        try:
            return hashlib.blake2b(text.encode('utf-8')).hexdigest()
        except Exception:
            raise ValueError("invalid_blake2b_input")

    @staticmethod
    def blake2s_hash_text(text):
        try:
            return hashlib.blake2s(text.encode('utf-8')).hexdigest()
        except Exception:
            raise ValueError("invalid_blake2s_input")

    @staticmethod
    def aes_encrypt(text, key):
        try:
            key = bytes.fromhex(key)
            if len(key) not in [16, 24, 32]:
                raise ValueError("invalid_aes_key")
            iv = secrets.token_bytes(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padder = sym_padding.PKCS7(128).padder()
            padded_data = padder.update(text.encode('utf-8')) + padder.finalize()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            return base64.b64encode(iv + ciphertext).decode('utf-8')
        except Exception:
            raise ValueError("invalid_aes_input")

    @staticmethod
    def aes_decrypt(text, key):
        try:
            data = base64.b64decode(text)
            key = bytes.fromhex(key)
            if len(key) not in [16, 24, 32]:
                raise ValueError("invalid_aes_key")
            iv = data[:16]
            ciphertext = data[16:]
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = sym_padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            return plaintext.decode('utf-8')
        except Exception:
            raise ValueError("invalid_aes_input")

    @staticmethod
    def blowfish_encrypt(text, key):
        try:
            key = bytes.fromhex(key)
            if len(key) < 4 or len(key) > 56:
                raise ValueError("invalid_blowfish_key")
            iv = secrets.token_bytes(8)
            cipher = blowfish.Cipher(key)
            padded_data = sym_padding.PKCS7(64).padder().update(text.encode('utf-8')) + sym_padding.PKCS7(64).padder().finalize()
            ciphertext = b''.join(cipher.encrypt_cbc(padded_data, iv))
            return base64.b64encode(iv + ciphertext).decode('utf-8')
        except Exception:
            raise ValueError("invalid_blowfish_input")

    @staticmethod
    def blowfish_decrypt(text, key):
        try:
            data = base64.b64decode(text)
            key = bytes.fromhex(key)
            if len(key) < 4 or len(key) > 56:
                raise ValueError("invalid_blowfish_key")
            iv = data[:8]
            ciphertext = data[8:]
            cipher = blowfish.Cipher(key)
            padded_plaintext = b''.join(cipher.decrypt_cbc(ciphertext, iv))
            plaintext = sym_padding.PKCS7(64).unpadder().update(padded_plaintext) + sym_padding.PKCS7(64).unpadder().finalize()
            return plaintext.decode('utf-8')
        except Exception:
            raise ValueError("invalid_blowfish_input")

    @staticmethod
    def chacha20_encrypt(text, key):
        try:
            key = bytes.fromhex(key)
            if len(key) != 32:
                raise ValueError("invalid_chacha20_key")
            nonce = secrets.token_bytes(16)
            cipher = Cipher(ChaCha20(key, nonce), mode=None, backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(text.encode('utf-8')) + encryptor.finalize()
            return base64.b64encode(nonce + ciphertext).decode('utf-8')
        except Exception:
            raise ValueError("invalid_chacha20_input")

    @staticmethod
    def chacha20_decrypt(text, key):
        try:
            data = base64.b64decode(text)
            key = bytes.fromhex(key)
            if len(key) != 32:
                raise ValueError("invalid_chacha20_key")
            nonce = data[:16]
            ciphertext = data[16:]
            cipher = Cipher(ChaCha20(key, nonce), mode=None, backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext.decode('utf-8')
        except Exception:
            raise ValueError("invalid_chacha20_input")

    @staticmethod
    def tripledes_encrypt(text, key):
        try:
            key = bytes.fromhex(key)
            if len(key) not in [16, 24]:
                raise ValueError("invalid_tripledes_key")
            iv = secrets.token_bytes(8)
            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padder = sym_padding.PKCS7(64).padder()
            padded_data = padder.update(text.encode('utf-8')) + padder.finalize()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            return base64.b64encode(iv + ciphertext).decode('utf-8')
        except Exception:
            raise ValueError("invalid_tripledes_input")

    @staticmethod
    def tripledes_decrypt(text, key):
        try:
            data = base64.b64decode(text)
            key = bytes.fromhex(key)
            if len(key) not in [16, 24]:
                raise ValueError("invalid_tripledes_key")
            iv = data[:8]
            ciphertext = data[8:]
            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = sym_padding.PKCS7(64).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            return plaintext.decode('utf-8')
        except Exception:
            raise ValueError("invalid_tripledes_input")

    @staticmethod
    def rsa_encrypt(text, public_key_pem):
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'), backend=default_backend())
            ciphertext = public_key.encrypt(
                text.encode('utf-8'),
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return base64.b64encode(ciphertext).decode('utf-8')
        except Exception:
            raise ValueError("invalid_rsa_input")

    @staticmethod
    def rsa_decrypt(text, private_key_pem):
        try:
            data = base64.b64decode(text)
            private_key = serialization.load_pem_private_key(private_key_pem.encode('utf-8'), password=None, backend=default_backend())
            plaintext = private_key.decrypt(
                data,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return plaintext.decode('utf-8')
        except Exception:
            raise ValueError("invalid_rsa_input")

    @staticmethod
    def aes_encrypt_binary(data: bytes, key: bytes, file_extension: str) -> bytes:
        try:
            if len(key) not in [16, 24, 32]:
                raise ValueError("invalid_aes_key")
            ext_bytes = file_extension.encode('utf-8')
            if len(ext_bytes) > 255:
                raise ValueError("extension_too_long")
            ext_length = len(ext_bytes).to_bytes(1, byteorder='big')
            iv = secrets.token_bytes(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padder = sym_padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            return ext_length + ext_bytes + iv + ciphertext
        except Exception as e:
            raise ValueError(f"file_encryption_error: {str(e)}")

    @staticmethod
    def aes_decrypt_binary(encrypted_data: bytes, key: bytes) -> tuple[bytes, str]:
        try:
            if len(encrypted_data) < 2:
                raise ValueError("invalid_encrypted_data: Data too short")
            if len(key) not in [16, 24, 32]:
                raise ValueError("invalid_aes_key")
            ext_length = int.from_bytes(encrypted_data[:1], byteorder='big')
            if ext_length < 0 or ext_length > len(encrypted_data) - 17:
                raise ValueError("invalid_extension_metadata: Invalid extension length")
            file_extension = encrypted_data[1:1+ext_length].decode('utf-8', errors='replace')
            iv = encrypted_data[1+ext_length:1+ext_length+16]
            ciphertext = encrypted_data[1+ext_length+16:]
            if len(iv) != 16 or len(ciphertext) < 1:
                raise ValueError("invalid_encrypted_data: Invalid IV or ciphertext")
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = sym_padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            return plaintext, file_extension
        except ValueError as e:
            raise ValueError(f"file_decryption_error: {str(e)}")
        except Exception as e:
            raise ValueError(f"file_decryption_error: {str(e)}")

    @staticmethod
    def blowfish_encrypt_binary(data: bytes, key: bytes, file_extension: str) -> bytes:
        try:
            if len(key) < 4 or len(key) > 56:
                raise ValueError("invalid_blowfish_key")
            ext_bytes = file_extension.encode('utf-8')
            if len(ext_bytes) > 255:
                raise ValueError("extension_too_long")
            ext_length = len(ext_bytes).to_bytes(1, byteorder='big')
            iv = secrets.token_bytes(8)
            cipher = blowfish.Cipher(key)
            padded_data = sym_padding.PKCS7(64).padder().update(data) + sym_padding.PKCS7(64).padder().finalize()
            ciphertext = b''.join(cipher.encrypt_cbc(padded_data, iv))
            return ext_length + ext_bytes + iv + ciphertext
        except Exception as e:
            raise ValueError(f"file_encryption_error: {str(e)}")

    @staticmethod
    def blowfish_decrypt_binary(encrypted_data: bytes, key: bytes) -> tuple[bytes, str]:
        try:
            if len(encrypted_data) < 2:
                raise ValueError("invalid_encrypted_data: Data too short")
            if len(key) < 4 or len(key) > 56:
                raise ValueError("invalid_blowfish_key")
            ext_length = int.from_bytes(encrypted_data[:1], byteorder='big')
            if ext_length < 0 or ext_length > len(encrypted_data) - 9:
                raise ValueError("invalid_extension_metadata: Invalid extension length")
            file_extension = encrypted_data[1:1+ext_length].decode('utf-8', errors='replace')
            iv = encrypted_data[1+ext_length:1+ext_length+8]
            ciphertext = encrypted_data[1+ext_length+8:]
            if len(iv) != 8 or len(ciphertext) < 1:
                raise ValueError("invalid_encrypted_data: Invalid IV or ciphertext")
            cipher = blowfish.Cipher(key)
            padded_plaintext = b''.join(cipher.decrypt_cbc(ciphertext, iv))
            plaintext = sym_padding.PKCS7(64).unpadder().update(padded_plaintext) + sym_padding.PKCS7(64).unpadder().finalize()
            return plaintext, file_extension
        except ValueError as e:
            raise ValueError(f"file_decryption_error: {str(e)}")
        except Exception as e:
            raise ValueError(f"file_decryption_error: {str(e)}")

    @staticmethod
    def chacha20_encrypt_binary(data: bytes, key: bytes, file_extension: str) -> bytes:
        try:
            if len(key) != 32:
                raise ValueError("invalid_chacha20_key")
            ext_bytes = file_extension.encode('utf-8')
            if len(ext_bytes) > 255:
                raise ValueError("extension_too_long")
            ext_length = len(ext_bytes).to_bytes(1, byteorder='big')
            nonce = secrets.token_bytes(16)
            cipher = Cipher(ChaCha20(key, nonce), mode=None, backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            return ext_length + ext_bytes + nonce + ciphertext
        except Exception as e:
            raise ValueError(f"file_encryption_error: {str(e)}")

    @staticmethod
    def chacha20_decrypt_binary(encrypted_data: bytes, key: bytes) -> tuple[bytes, str]:
        try:
            if len(encrypted_data) < 2:
                raise ValueError("invalid_encrypted_data: Data too short")
            if len(key) != 32:
                raise ValueError("invalid_chacha20_key")
            ext_length = int.from_bytes(encrypted_data[:1], byteorder='big')
            if ext_length < 0 or ext_length > len(encrypted_data) - 17:
                raise ValueError("invalid_extension_metadata: Invalid extension length")
            file_extension = encrypted_data[1:1+ext_length].decode('utf-8', errors='replace')
            nonce = encrypted_data[1+ext_length:1+ext_length+16]
            ciphertext = encrypted_data[1+ext_length+16:]
            if len(nonce) != 16 or len(ciphertext) < 1:
                raise ValueError("invalid_encrypted_data: Invalid nonce or ciphertext")
            cipher = Cipher(ChaCha20(key, nonce), mode=None, backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext, file_extension
        except ValueError as e:
            raise ValueError(f"file_decryption_error: {str(e)}")
        except Exception as e:
            raise ValueError(f"file_decryption_error: {str(e)}")

    @staticmethod
    def tripledes_encrypt_binary(data: bytes, key: bytes, file_extension: str) -> bytes:
        try:
            if len(key) not in [16, 24]:
                raise ValueError("invalid_tripledes_key")
            ext_bytes = file_extension.encode('utf-8')
            if len(ext_bytes) > 255:
                raise ValueError("extension_too_long")
            ext_length = len(ext_bytes).to_bytes(1, byteorder='big')
            iv = secrets.token_bytes(8)
            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padder = sym_padding.PKCS7(64).padder()
            padded_data = padder.update(data) + padder.finalize()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            return ext_length + ext_bytes + iv + ciphertext
        except Exception as e:
            raise ValueError(f"file_encryption_error: {str(e)}")

    @staticmethod
    def tripledes_decrypt_binary(encrypted_data: bytes, key: bytes) -> tuple[bytes, str]:
        try:
            if len(encrypted_data) < 2:
                raise ValueError("invalid_encrypted_data: Data too short")
            if len(key) not in [16, 24]:
                raise ValueError("invalid_tripledes_key")
            ext_length = int.from_bytes(encrypted_data[:1], byteorder='big')
            if ext_length < 0 or ext_length > len(encrypted_data) - 9:
                raise ValueError("invalid_extension_metadata: Invalid extension length")
            file_extension = encrypted_data[1:1+ext_length].decode('utf-8', errors='replace')
            iv = encrypted_data[1+ext_length:1+ext_length+8]
            ciphertext = encrypted_data[1+ext_length+8:]
            if len(iv) != 8 or len(ciphertext) < 1:
                raise ValueError("invalid_encrypted_data: Invalid IV or ciphertext")
            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = sym_padding.PKCS7(64).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            return plaintext, file_extension
        except ValueError as e:
            raise ValueError(f"file_decryption_error: {str(e)}")
        except Exception as e:
            raise ValueError(f"file_decryption_error: {str(e)}")

    @staticmethod
    def generate_key(key_size_bits):
        try:
            if key_size_bits <= 0:
                raise ValueError("key_generation_error_title")
            key_size_bytes = key_size_bits // 8
            if key_size_bytes == 0:
                key_size_bytes = 1
            return secrets.token_hex(key_size_bytes)
        except ValueError:
            raise

    @staticmethod
    def generate_rsa_key_pair(key_size):
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
            public_key = private_key.public_key()
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            return private_pem, public_pem
        except Exception:
            raise ValueError("key_generation_error_title")

    @staticmethod
    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a