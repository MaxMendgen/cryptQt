import re
from unidecode import unidecode

def makeFile(text: str, filename: str) -> None:
    """
    makeFile takes a string and turns it into a utf-8 file

    :param text: string to be turned into a file
    :param filename: name of the file to be written to
    :return: None, output is written to a file
    """   
    with open(filename, "w", encoding="utf-8") as f:
        f.write(text)

def txtToString(filename: str) -> str:
    """
    txtToString takes a utf-8 file and turns it into a str

    :param filename: name of the file to be read
    :return: str of the read content
    """ 
    with open(filename, "r", encoding="utf8") as f:
        content = f.read()
        return content

def normalize_string(text: str) -> str:
    """
    Standardizes text for classic cryptography.
    Converts special characters to their multi-letter Latin equivalents 
    and strips remaining diacritics. e.g. 'ä' → 'AE', 'é' → 'E', 'ç' → 'C'.

    :param text: The input string to normalize.
    :return: A normalized string containing only uppercase A-Z characters.
    """
    
    # Manual mapping for expansions (Digraphs)
    expansions = {
        # German
        'ä': 'ae', 'ö': 'oe', 'ü': 'ue', 'ß': 'ss',
        'Ä': 'AE', 'Ö': 'OE', 'Ü': 'UE', 'ẞ': 'SS',
        # Scandinavian / Icelandic
        'æ': 'ae', 'ø': 'oe', 'å': 'aa', 'þ': 'th',
        'Æ': 'AE', 'Ø': 'OE', 'Å': 'AA', 'Þ': 'TH',
        # French / Latin
        'œ': 'oe', 'Œ': 'OE',
        # Spanish (historical telegram style)
        'ñ': 'nn', 'Ñ': 'NN' 
    }

    # Apply expansions
    for char, replacement in expansions.items():
        text = text.replace(char, replacement)

    return unidecode(text)

def solidify_string(text: str) -> str:
    """
    solidify_string uppercases the input and removes empty spaces,
    but preserves special characters.

    :param text: The input string to solidify.
    :return: A solidified string containing uppercase letters and symbols.
    """
    return ''.join(ch.upper() for ch in text if not ch.isspace())
