# cryptqt/__init__.py

# ----- Core crypto -----
from .core_crypto.analysis_tools import (
    ceasar_analysis,
    vigenere_square,
    kasiski_test,
    kasiski_key,
)

from .core_crypto.attack_tools import (
    ceasar_brute_force
)

from .core_crypto.crypto_tools import (
    ceasar_encrypt,
    ceasar_decrypt,
    vigenere_decrypt,
    vigenere_encrypt,
    otp,
    rsa_decrypt,
    rsa_encrypt,
    aes_decrypt,
    aes_encrypt,
    generate_rsa_keys,
    load_private_key,
    load_public_key,
)

# ----- File utilities -----
from .fileutils.raw_utils import (
    file_to_string,
)
from .fileutils.txt_utils import (
    makeFile,
    txtToString,
    normalize_string,
    solidify_string
)

# ----- Public API -----
__all__ = [
    # Core crypto
    "ceasar_analysis", "vigenere_square", "kasiski_test", "kasiski_key",
    "ceasar_encrypt", "ceasar_decrypt", "vigenere_decrypt", "vigenere_encrypt",
    "otp", "rsa_decrypt", "rsa_encrypt", "aes_decrypt", "aes_encrypt",
    "generate_rsa_keys", "load_private_key", "load_public_key",
    "ceasar_brute_force",

    # File utils
    "file_to_string", "txtToString", "makeFile", "normalize_string", "solidify_string"
]
