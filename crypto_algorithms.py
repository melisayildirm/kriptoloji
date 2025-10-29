# -*- coding: utf-8 -*-

import string

# --- 1. Caesar Cipher ---
def caesar_encrypt(text, shift=3):
    result = ""
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - start + shift) % 26 + start)
        else:
            result += char
    return result

def caesar_decrypt(text, shift=3):
    return caesar_encrypt(text, -shift)


# --- 2. Vigenere Cipher ---
def vigenere_encrypt(text, key):
    result, key_index = "", 0
    key = key.lower()
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('a')
            start = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - start + shift) % 26 + start)
            key_index += 1
        else:
            result += char
    return result

def vigenere_decrypt(text, key):
    result, key_index = "", 0
    key = key.lower()
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('a')
            start = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - start - shift) % 26 + start)
            key_index += 1
        else:
            result += char
    return result


# --- 3. Substitution Cipher ---
alphabet = string.ascii_lowercase

def substitution_encrypt(text, key):
    table = str.maketrans(alphabet, key)
    return text.lower().translate(table)

def substitution_decrypt(text, key):
    table = str.maketrans(key, alphabet)
    return text.lower().translate(table)


# --- 4. Affine Cipher ---
def affine_encrypt(text, a=5, b=8):
    result = ""
    for char in text:
        if char.isalpha():
            x = ord(char.lower()) - ord('a')
            enc = (a * x + b) % 26
            result += chr(enc + ord('a'))
        else:
            result += char
    return result

def affine_decrypt(text, a=5, b=8):
    result = ""
    a_inv = pow(a, -1, 26)  # modüler ters
    for char in text:
        if char.isalpha():
            y = ord(char.lower()) - ord('a')
            dec = (a_inv * (y - b)) % 26
            result += chr(dec + ord('a'))
        else:
            result += char
    return result


# --- 5. Rail Fence Cipher ---
def rail_fence_encrypt(text, rails=3):
    if rails < 2:
        return text

    rows = ["" for _ in range(rails)]
    cycle = 2 * (rails - 1)

    for i, ch in enumerate(text):
        t = i % cycle
        row = t if t < rails else cycle - t
        rows[row] += ch

    return "".join(rows)


def rail_fence_decrypt(text, rails=3):
    if rails < 2:
        return text

    n = len(text)
    cycle = 2 * (rails - 1)

    pattern = []
    for i in range(n):
        t = i % cycle
        row = t if t < rails else cycle - t
        pattern.append(row)

    counts = [0] * rails
    for r in pattern:
        counts[r] += 1

    parts = []
    idx = 0
    for c in counts:
        parts.append(list(text[idx:idx + c]))
        idx += c

    result = []
    ptr = [0] * rails
    for r in pattern:
        result.append(parts[r][ptr[r]])
        ptr[r] += 1

    return "".join(result)