from cryptqt.core_crypto.crypto_tools import ceasar_decrypt

def ceasar_brute_force(ciphertext: str) -> dict:
    """
    ceasar_brute_force takes a string and returns a dict of all 26 possible decodings

    :param ciphertext: string to be decoded
    :return: dict of all 26 possible decodings
    """
    return {key: ceasar_decrypt(ciphertext, key) for key in range(26)}

