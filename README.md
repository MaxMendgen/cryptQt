# CryptQT 
## a simple QT tool to encrypt and decrypt text

CryptQT is a simple graphical tool built with Qt for encrypting and decrypting files. It supports:

- Encrypting files using various cryptographic algorithms:
	- Caesar cipher
	- Vigenère cipher
	- One-Time Pad (OTP)
	- AES (Advanced Encryption Standard)
	- RSA (Rivest–Shamir–Adleman)
- Decrypting files that were previously encrypted
- Managing encryption keys
- Analyzing and attacking encrypted files (for educational purposes)

### How to Use


1. Make sure you have Python installed.
2. Simply run the application by executing:
   
	```
	python main.py
	```
	- The program will automatically install all required dependencies from requirements.txt if needed.
3. Use the graphical interface to select files, choose encryption/decryption options, and manage keys.
	- You can open files, save output, and generate RSA keys directly from the GUI.
	- Built-in analysis tools help you break or analyze Caesar and Vigenère ciphers.

No command-line arguments are required; just run main.py and follow the GUI prompts.

---
© by Max Mendgen and Leonie Riedel Licensed under the EUPL
