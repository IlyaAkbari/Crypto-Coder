# Crypto Coder

CryptoCoder is a comprehensive PyQt6-based desktop application for cryptographic operations. It supports various levels of encryption, decryption, hashing, encoding/decoding, algorithm mixing, file encryption, and smart decryption. The app features multi-language support (English, Persian, Arabic), theme customization (light/dark), and an intuitive user interface with animated elements.

## Features

- **Ciphers (Level 1)**: Caesar, Vigenere, Affine, Atbash, Reverse String, Rail Fence, Simple Substitution, Playfair, Polybius Square.
- **Encoders/Decoders (Level 2)**: Base64, ROT13, URL Encoding, Hex, ASCII, Binary, Morse Code, Quoted-Printable, Unicode Escape, Base32, UUEncode.
- **Hashers (Level 3)**: MD5, SHA1, SHA224, SHA256, SHA384, SHA512, SHA3_256, SHA3_512, Whirlpool, Blake2b, Blake2s.
- **Advanced Encryption (Level 4)**: AES, RSA, Blowfish, ChaCha20, TripleDES (with key generation).
- **Smart Decrypt (Level 5)**: Intelligent decryption using heuristics, ML models, GPU acceleration (via Numba/CUDA), and multi-threading for cracking hashes/ciphers.
- **Algorithm Mixer (Level 6)**: Combine multiple algorithms for layered encryption.
- **File Encryption (Level 7)**: Encrypt/decrypt files/folders using symmetric algorithms, with metadata preservation.
- **Settings (Level 8)**: Theme toggle (light/dark), language selection, custom button colors, about section.
- **Additional Utilities**: Clipboard integration, error handling, progress bars for long operations, and hardware-accelerated computations.

## Repository Structure
Crypto-Coder/
├── README.md                  # This file
├── .gitignore                 # Git ignore file for Python projects
├── requirements.txt           # Dependencies
├── main.py                    # Main application entry point
├── animated_combobox.py       # Custom animated QComboBox widget
├── crypto_utils.py            # Core cryptographic utilities and functions
├── language_strings.py        # Multi-language string dictionaries
├── page1_ciphers.py           # UI and logic for Level 1: Ciphers
├── page2_encoders_decoders.py # UI and logic for Level 2: Encoders/Decoders
├── page3_hashers.py           # UI and logic for Level 3: Hashers
├── page4_advanced_encryption.py # UI and logic for Level 4: Advanced Encryption
├── page5_smart_decrypt.py     # UI and logic for Level 5: Smart Decrypt
├── page6_algorithm_mixer.py   # UI and logic for Level 6: Algorithm Mixer
├── page7_file_encryption.py   # UI and logic for Level 7: File Encryption
├── page8_settings.py          # UI and logic for Level 8: Settings
├── toggle_switch.py           # Custom toggle switch widget for themes
└── Images/
└── Icon.ico               # Application icon


## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/IlyaAkbari/Crypto-Coder.git
   cd Crypto-Coder
2. **Set Up Virtual Environment (Recommended)**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Unix/Mac
   venv\Scripts\activate     # On Windows
3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   
Note: Some advanced features in crypto_utils.py and page5_smart_decrypt.py require additional libraries like cryptography, pycryptodome (for Whirlpool), numpy, scikit-learn, numba, etc. Ensure CUDA is installed for GPU acceleration if available.

4. **Run the application**:python main.py
