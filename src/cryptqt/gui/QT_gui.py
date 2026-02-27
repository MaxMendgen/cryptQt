import sys
import os
from PySide6.QtWidgets import (
    QApplication, QWidget,
    QHBoxLayout, QVBoxLayout,
    QPushButton, QTextEdit, QLabel,
    QLineEdit, QFileDialog, QMessageBox,
    QComboBox
)
from cryptqt import *

# ================= GUI =================

class CryptoGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Crypto Toolkit")
        self.resize(900, 550)

        # ---- state ----
        self.current_file_path = None
        self.current_file_name = None

        self.ensure_dirs()

        # ===== LEFT BUTTONS =====

        self.encrypt_btn = QPushButton("Encrypt")
        self.decrypt_btn = QPushButton("Decrypt")
        self.open_btn = QPushButton("Open File")
        self.save_output_btn = QPushButton("Save Output as File")
        self.generate_keys_btn = QPushButton("Generate RSA Keys")
        self.normalize_text_btn = QPushButton("Lossy Normalize Text")
        self.solidify_text_btn = QPushButton("Solidify Text")
        self.clear_fields_btn = QPushButton("Clear Fields")

        self.caesar_analysis_btn = QPushButton("Caesar Analysis")
        self.caesar_brute_force_btn = QPushButton("Caesar Brute Force")
        self.vigenere_analysis_btn = QPushButton("Vigenere Analysis (Kasiski)")
        self.vigenere_square_btn = QPushButton("Vigenere Square")

        left_layout = QVBoxLayout()
        left_layout.addWidget(self.encrypt_btn)
        left_layout.addWidget(self.decrypt_btn)
        left_layout.addWidget(self.open_btn)
        left_layout.addWidget(self.save_output_btn)
        left_layout.addWidget(self.generate_keys_btn)
        left_layout.addWidget(self.normalize_text_btn)
        left_layout.addWidget(self.solidify_text_btn)
        left_layout.addWidget(self.clear_fields_btn)
        left_layout.addSpacing(20)
        left_layout.addWidget(self.caesar_analysis_btn)
        left_layout.addWidget(self.caesar_brute_force_btn)
        left_layout.addWidget(self.vigenere_analysis_btn)
        left_layout.addWidget(self.vigenere_square_btn)
        left_layout.addStretch()

        # ===== RIGHT SIDE =====
        self.algorithm_box = QComboBox()
        self.algo_caeser = "Caesar"
        self.algo_vigenere = "Vigenere"
        self.algo_otp = "OTP (One Time Pad)"
        self.algo_aes = "AES (Advanced Encryption Standard)"
        self.algo_rsa = "RSA (Rivest-Shamir-Adleman)"
        self.algorithm_box.addItems([
            self.algo_caeser,
            self.algo_vigenere,
            self.algo_otp,
            self.algo_aes,
            self.algo_rsa
        ])

        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Key / Password")

        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Input text or file content...")

        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)

        right_layout = QVBoxLayout()
        right_layout.addWidget(QLabel("Algorithm"))
        right_layout.addWidget(self.algorithm_box)
        right_layout.addWidget(QLabel("Key"))
        right_layout.addWidget(self.key_input)
        right_layout.addWidget(QLabel("Input"))
        right_layout.addWidget(self.input_text)
        right_layout.addWidget(QLabel("Output"))
        right_layout.addWidget(self.output_text)

        # ===== MAIN LAYOUT =====
        main_layout = QHBoxLayout()
        main_layout.addLayout(left_layout)
        main_layout.addLayout(right_layout)
        main_layout.setStretch(0, 1)
        main_layout.setStretch(1, 4)
        self.setLayout(main_layout)

        # ===== SIGNALS =====
        self.encrypt_btn.clicked.connect(self.encrypt)
        self.decrypt_btn.clicked.connect(self.decrypt)
        self.open_btn.clicked.connect(self.open_file)
        self.generate_keys_btn.clicked.connect(self.generate_rsa_keys)
        self.save_output_btn.clicked.connect(self.save_output_as_file)
        self.clear_fields_btn.clicked.connect(self.clear_fields)
        self.normalize_text_btn.clicked.connect(self.normalize_text)
        self.solidify_text_btn.clicked.connect(self.solidify_text)

        self.caesar_analysis_btn.clicked.connect(self.run_caesar_analysis)
        self.caesar_brute_force_btn.clicked.connect(self.run_caesar_brute_force)
        self.vigenere_analysis_btn.clicked.connect(self.run_vigenere_analysis)
        self.vigenere_square_btn.clicked.connect(self.run_vigenere_square)

    # ================= HELPERS =================

    def ensure_dirs(self):
        os.makedirs("files/encrypted", exist_ok=True)
        os.makedirs("files/decrypted", exist_ok=True)
        os.makedirs("files/keys", exist_ok=True)

    def error(self, msg):
        print(f"Error: {msg}")
        QMessageBox.critical(self, "Error", msg)

    def common(self):
        return (
            self.algorithm_box.currentText(),
            self.key_input.text(),
            self.input_text.toPlainText()
        )

    # ================= FILE HANDLING =================

    def open_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open file")
        if not path:
            return

        try:
            self.current_file_path = path
            self.current_file_name = os.path.basename(path)

            content = txtToString(path) #file_to_string was extremely buggy and caused shit
            self.input_text.setPlainText(content)

        except Exception as e:
            self.error(f"{type(e).__name__}: {e}")

    def save_output_as_file(self):
        """Manual save, for text typed in the box"""
        content = self.output_text.toPlainText()
        if not content:
            self.error("No output to save!")
            return

        path, _ = QFileDialog.getSaveFileName(self, "Save output as file")
        if not path:
            return

        try:
            makeFile(content, path)
            QMessageBox.information(self, "Saved", f"Output saved to:\n{path}")
        except Exception as e:
            self.error(f"{type(e).__name__}: {e}")

    # ================= RSA KEYS =================

    def generate_rsa_keys(self):
        try:
            key_path = "files/keys"
            generate_rsa_keys()
            os.replace("public_key.pem", f"{key_path}/public_key.pem")
            os.replace("private_key.pem", f"{key_path}/private_key.pem")
            QMessageBox.information(self, "RSA Keys", f"Keys saved to {key_path}")
        except Exception as e:
            self.error(f"{type(e).__name__}: {e}")

    # ================= ENCRYPT =================

    def encrypt(self):
        algo, key, text = self.common()

        try:
            if algo == self.algo_caeser:
                result = ceasar_encrypt(text, key)
            elif algo == self.algo_vigenere:
                result = vigenere_encrypt(text, key)
            elif algo == self.algo_otp:
                result = otp(text, key)
            elif algo == self.algo_aes:
                result = aes_encrypt(key, text)
            elif algo == self.algo_rsa:
                key_path = "files/keys"
                if not os.path.exists(f"{key_path}/public_key.pem"):
                    self.generate_rsa_keys()
                pub = load_public_key(f"{key_path}/public_key.pem")
                result = rsa_encrypt(pub, text)
            else:
                self.error("Unknown algorithm")
                return
            # IGNORE I FUCKED UP
            # If input is from a file, automatically save encrypted file
            """ if self.current_file_path:
                out_name = self.current_file_name + ".crypt"
                out_path = os.path.join("files/encrypted", out_name)
                makefile(result, out_path)
                self.output_text.setPlainText(f"Encrypted file saved to:\n{out_path}")
            else: """
            self.output_text.setPlainText(result)

        except Exception as e:
            self.error(f"{type(e).__name__}: {e}")

    # ================= DECRYPT =================

    def decrypt(self):
        algo, key, text = self.common()

        try:
            if algo == self.algo_caeser:
                result = ceasar_decrypt(text, key)
            elif algo == self.algo_vigenere:
                result = vigenere_decrypt(text, key)
            elif algo == self.algo_otp:
                result = otp(text, key)
            elif algo == self.algo_aes:
                result = aes_decrypt(key, text)
            elif algo == self.algo_rsa:
                priv = load_private_key("files/keys/private_key.pem", key or None)
                result = rsa_decrypt(priv, text)
            else:
                self.error("Unknown algorithm")
                return

            """   # If file ends with .crypt, automatically save decrypted file
            if self.current_file_path and self.current_file_name.endswith(".crypt"):
                name = self.current_file_name[:-6]  # remove .crypt
                out_path = os.path.join("files/decrypted", name)
                makefile(result, out_path)
                self.output_text.setPlainText(f"Decrypted file saved to:\n{out_path}")
            else: """
            self.output_text.setPlainText(result)

        except Exception as e:
            self.error(f"{type(e).__name__}: {e}")

    # ================= ANALYSIS =================

    def run_caesar_analysis(self):
        try:
            text = self.input_text.toPlainText()
            result = ceasar_analysis(text)
            self.output_text.setPlainText("\n".join(result))
        except Exception as e:
            self.error(f"{type(e).__name__}: {e}")

    def run_caesar_brute_force(self):
        try:
            text = self.input_text.toPlainText()
            results = ceasar_brute_force(text)
            output = "\n\n".join([f"Key {key}:\n{dec}" for key, dec in results.items()])
            self.output_text.setPlainText(output)
        except Exception as e:
            self.error(f"{type(e).__name__}: {e}")

    def run_vigenere_analysis(self):
        try:
            text = self.input_text.toPlainText()
            kasiski = kasiski_test(text)
            key_len = kasiski_key(kasiski)
            self.output_text.setPlainText(
                f"Kasiski test result:\n{kasiski}\n\nMost likely key length: {key_len}"
            )
        except Exception as e:
            self.error(f"{type(e).__name__}: {e}")

    def run_vigenere_square(self):
        square = vigenere_square()
        self.output_text.setPlainText(square)

    # ================= TEXT HANDLING =================

    def normalize_text(self):
        text = self.input_text.toPlainText()
        normalized = normalize_string(text)
        self.input_text.setPlainText(normalized)

    def solidify_text(self):
        text = self.input_text.toPlainText()
        solidified = solidify_string(text)
        self.input_text.setPlainText(solidified)

    def clear_fields(self):
        reply = QMessageBox.question(self, "Clear Fields", "Are you sure you want to clear all fields?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.input_text.clear()
            self.key_input.clear()
            self.output_text.clear()

# ================= RUN =================

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = CryptoGUI()
    win.show()
    sys.exit(app.exec())
