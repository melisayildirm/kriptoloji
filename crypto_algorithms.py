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
