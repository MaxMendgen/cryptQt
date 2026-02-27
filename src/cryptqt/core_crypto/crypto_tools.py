"--- Ceasar Functions ---"
def ceasar_encrypt(text: str, key: int | str) -> str:
    """
    ceasar_encrypt encodes any given string to ceasar encoding given a key

    :param text: string to be encoded
    :param key: key to encode with (number or letter, e.g. 3 or C)
    :return: string of encoded text
    """

    key = check_ceasar_key(key)
    result = []
    for l in text:
        if l.isalpha() and l.isascii():
            base = ord("A") if l.isupper() else ord("a") #Set the base letter, A is we start with an upper letter else a, we need a base because ASCII
            shift = (ord(l) - base + key) % 26 + base
            result.append(chr(shift))
        else:
            result.append(l) #do not encrypt a character that is not alphabetical (e.g. .!?)
    return "".join(result)

def ceasar_decrypt(text: str, key: int | str) -> str:
    """
    ceasar_decrypt decodes any given string in ceasar encoding given a key

    :param text: string to be decoded
    :param key: key to decode with
    :return: string of decoded text
    """

    key = check_ceasar_key(key)
    return ceasar_encrypt(text, -key) #literally just encrypt but reverse

def check_ceasar_key(key: int | str) -> int:
    """check_ceasar_key checks if the key is valid and converts it to an integer if it's a letter"""
    if isinstance(key, str):
        try:
            key = int(key)
        except ValueError:
            if len(key) > 1:
                raise ValueError("Key must be a single letter or a number")
            if not key.isalpha() and key.isascii():
                raise ValueError("Key must be a letter or a number")
            key = ord(key.upper()) - ord("A")
    return key

"--- Vigenere Functions ---"
def vigenere_encrypt(text: str, key: str) -> str:
    """
    vigenere_encrypt encodes any given string to vigenere encoding given a key

    :param text: string to be encoded
    :param key: key to encode with
    :return: string of encoded text
    """
    if not key.isalpha() and key.isascii():
        raise ValueError("Key must be a string of valid letters")
    return "".join(
        chr((ord(ch) - (ord("A") if ch.isupper() else ord("a")) + (ord(key[i % len(key)].upper()) - ord("A"))) % 26 + (ord("A") if ch.isupper() else ord("a")))
        #(ch - base + shift) %26 + base
        if ch.isalpha() and ch.isascii() else ch
        for i, ch in enumerate(text))

def vigenere_decrypt(text:str, key:str) -> str:
    """
    vigenere_decrypt decodes any given string in vigenere encoding given a key

    :param text: string to be decoded
    :param key: key to decode with
    :return: string of decoded text
    """
    if not key.isalpha() and key.isascii():
        raise ValueError("Key must be a string of valid letters")
    return "".join(
        chr((ord(ch) - (ord("A") if ch.isupper() else ord("a")) - (ord(key[i % len(key)].upper()) - ord("A"))) % 26 + (ord("A") if ch.isupper() else ord("a")))
        #(ch - base - shift) %26 + base
        if ch.isalpha() and ch.isascii() else ch
        for i, ch in enumerate(text))

"--- OTP Functions ---"
def otp(text: str, key: str) -> str:
    """
    otp encodes/decodes any given string to and from one-time-pad encoding given a key
    
    :param text: string to be encoded/decoded
    :param key: key to de/encode with
    :return: string of de/encoded text
    """
    if len(key) < len(text):
          raise ValueError("Key must be at least as long as text")
    return "".join(
          chr(ord(ch) ^ ord(key[i]))
          for i, ch in enumerate(text))

"--- AES Functions ---"
import os, base64
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def aes_encrypt(key: str, plaintext: str) -> str:
    salt = os.urandom(16)
    nonce = os.urandom(12)

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    derived_key = kdf.derive(key.encode())

    aesgcm = AESGCM(derived_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)

    payload = b"\x01" + salt + nonce + ciphertext
    return base64.urlsafe_b64encode(payload).decode()

def aes_decrypt(key: str, token: str) -> str:
    data = base64.urlsafe_b64decode(token.encode())

    version = data[0]
    salt = data[1:17]
    nonce = data[17:29]
    ciphertext = data[29:]

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    derived_key = kdf.derive(key.encode())

    aesgcm = AESGCM(derived_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return plaintext.decode()

"--- RSA Functions ---"
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

def generate_rsa_keys(passphrase: str | None = None):
    """
    Generates a new 2048-bit RSA key pair.
    Optionally encrypts the private key with a passphrase.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Save private key as PEM
    encryption_algo = serialization.BestAvailableEncryption(passphrase.encode()) if passphrase else serialization.NoEncryption()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algo
    )
    with open("private_key.pem", "wb") as f:
        f.write(private_pem)

    # Save public key as PEM
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("public_key.pem", "wb") as f:
        f.write(public_pem)

    print("Keys saved to private_key.pem and public_key.pem")
    return private_key, public_key

def load_private_key(path: str, passphrase: str | None = None):
    with open(path, "rb") as f:
        pem_data = f.read()
    private_key = serialization.load_pem_private_key(
        pem_data,
        password=passphrase.encode() if passphrase else None
    )
    return private_key

def load_public_key(path: str):
    with open(path, "rb") as f:
        pem_data = f.read()
    public_key = serialization.load_pem_public_key(pem_data)
    return public_key

def rsa_encrypt(public_key, plaintext: str) -> str:
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()

def rsa_decrypt(private_key, ciphertext_b64: str) -> str:
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()


# might be cooler to do the seperations like:

# ----------------------------
# Encrypt & decrypt functions
# ---------------------------- 


