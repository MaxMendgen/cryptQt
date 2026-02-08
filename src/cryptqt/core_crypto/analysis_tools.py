"--- Ceasar Analysis ---"
def countOccurences(text:str) -> dict:
    count = {}
    for ch in text:
        if ch in count:
            count[ch] += 1
        else: count[ch] = 1
    return count

def sortDict(dictionary: dict) -> list[tuple[str, int]]:
    return sorted(dictionary.items(), key=lambda x: x[1], reverse=True)

def mostLikelyLetter(sorted_letters: list[tuple[str, int]]) -> list[str]:
    mostLikelyLetters = ["E", "N", "I", "S", "R", "A", "T", "D", "H", "U", "L", "C", "G", "M", "O", "B", "W", "F", "K", "Z", "P", "V", "ß", "J", "Y", "X", "Q"]
    return [
        f"{letter}  → {mostLikelyLetters[i]}"
        for i, (letter, count) in enumerate(sorted_letters)
        if i < len(mostLikelyLetters) ]

def ceasar_analysis(str):
    return mostLikelyLetter(sortDict(countOccurences(str)))

"--- Vigenere Analysis ---"
def vigenere_square():
    return """
    # A B C D E F G H I J K L M N O P Q R S T U V W X Y Z  
    A A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
    B B C D E F G H I J K L M N O P Q R S T U V W X Y Z A
    C C D E F G H I J K L M N O P Q R S T U V W X Y Z A B
    D D E F G H I J K L M N O P Q R S T U V W X Y Z A B C
    E E F G H I J K L M N O P Q R S T U V W X Y Z A B C D
    F F G H I J K L M N O P Q R S T U V W X Y Z A B C D E
    G G H I J K L M N O P Q R S T U V W X Y Z A B C D E F
    H H I J K L M N O P Q R S T U V W X Y Z A B C D E F G
    I I J K L M N O P Q R S T U V W X Y Z A B C D E F G H
    J J K L M N O P Q R S T U V W X Y Z A B C D E F G H I
    K K L M N O P Q R S T U V W X Y Z A B C D E F G H I J
    L L M N O P Q R S T U V W X Y Z A B C D E F G H I J K
    M M N O P Q R S T U V W X Y Z A B C D E F G H I J K L
    N N O P Q R S T U V W X Y Z A B C D E F G H I J K L M
    O O P Q R S T U V W X Y Z A B C D E F G H I J K L M N
    P P Q R S T U V W X Y Z A B C D E F G H I J K L M N O
    Q Q R S T U V W X Y Z A B C D E F G H I J K L M N O P
    R R S T U V W X Y Z A B C D E F G H I J K L M N O P Q
    S S T U V W X Y Z A B C D E F G H I J K L M N O P Q R
    T T U V W X Y Z A B C D E F G H I J K L M N O P Q R S
    U U V W X Y Z A B C D E F G H I J K L M N O P Q R S T
    V V W X Y Z A B C D E F G H I J K L M N O P Q R S T U
    W W X Y Z A B C D E F G H I J K L M N O P Q R S T U V
    X X Y Z A B C D E F G H I J K L M N O P Q R S T U V W
    Y Y Z A B C D E F G H I J K L M N O P Q R S T U V W X
    Z Z A B C D E F G H I J K L M N O P Q R S T U V W X Y
    """


from math import gcd
def kasiski_test(ciphertext, min_len=3, max_len=5) -> dict:
    ciphertext = ''.join(filter(str.isalpha, ciphertext.upper()))
    repeats = {}

    #find repeated substrings
    for size in range(min_len, max_len + 1):
        for i in range(len(ciphertext) - size):
            sub = ciphertext[i:i + size]
            if sub not in repeats:
                repeats[sub] = []
            repeats[sub].append(i)

    #get distances between repeated occurrences
    distances = []
    for positions in repeats.values():
        if len(positions) > 1:
            for i in range(len(positions) - 1):
                distances.append(positions[i + 1] - positions[i])

    #compute GCDs of distances
    gcds = {}
    for i in range(len(distances)):
        for j in range(i + 1, len(distances)):
            g = gcd(distances[i], distances[j])
            if g > 1:
                if g in gcds:
                    gcds[g] += 1
                else:
                    gcds[g] = 1

    return dict(sorted(gcds.items(), key=lambda x: -x[1]))

def kasiski_key(test_result:dict) -> str:
    return next(iter(test_result))
