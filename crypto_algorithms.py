# -*- coding: utf-8 -*-
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
import base64

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


# --- 6. Route Cipher ---
def route_encrypt(text, width=5, direction='clockwise', fill_char='X'):
    """
    Route Cipher (Rota Şifresi) - spiral okuma ile şifreleme
    
    Args:
        text: Şifrelenecek metin
        width: Grid genişliği (yatay uzunluk)
        direction: 'clockwise' veya 'counterclockwise' (saat yönünde veya tersi)
        fill_char: Boşlukları doldurmak için kullanılacak karakter (default: 'X')
    
    Returns:
        Şifrelenmiş metin
    """
    # Metni temizle ve boşlukları kaldır
    clean_text = ''.join(text.split()).upper()
    
    # Grid'i oluştur
    rows = []
    for i in range(0, len(clean_text), width):
        row = list(clean_text[i:i+width])
        # Eksik hücreleri doldur
        while len(row) < width:
            row.append(fill_char)
        rows.append(row)
    
    if not rows:
        return ""
    
    rows_count = len(rows)
    
    # Spiral okuma için yönler
    directions_clockwise = [(0, -1), (1, 0), (0, 1), (-1, 0)]  # sol, aşağı, sağ, yukarı
    directions_counterclockwise = [(0, 1), (1, 0), (0, -1), (-1, 0)]  # sağ, aşağı, sol, yukarı
    
    directions = directions_clockwise if direction == 'clockwise' else directions_counterclockwise
    
    # Başlangıç: sağ üst köşe (0, width-1)
    result = []
    visited = [[False] * width for _ in range(rows_count)]
    
    r, c = 0, width - 1
    dir_idx = 0  # İlk yön: sola doğru
    remaining = rows_count * width
    
    while remaining > 0:
        result.append(rows[r][c])
        visited[r][c] = True
        remaining -= 1
        
        # Bir sonraki adımı dene
        dr, dc = directions[dir_idx]
        nr, nc = r + dr, c + dc
        
        # Eğer sınır dışına çıkıyorsa veya ziyaret edildiyse, yön değiştir
        if nr < 0 or nr >= rows_count or nc < 0 or nc >= width or visited[nr][nc]:
            dir_idx = (dir_idx + 1) % 4
            dr, dc = directions[dir_idx]
            nr, nc = r + dr, c + dc
        
        r, c = nr, nc
    
    return ''.join(result)


def route_decrypt(text, width=5, direction='clockwise', fill_char='X'):
    """
    Route Cipher ile şifrelenmiş metni çözer
    
    Args:
        text: Şifrelenmiş metin
        width: Grid genişliği (şifreleme sırasında kullanılan)
        direction: 'clockwise' veya 'counterclockwise'
        fill_char: Boşlukları doldurmak için kullanılan karakter
    
    Returns:
        Çözülmüş metin
    """
    if not text:
        return ""
    
    text = text.upper()
    n = len(text)
    rows_count = (n + width - 1) // width
    
    # Grid'i oluştur ve spiral yolu takip et
    grid = [[''] * width for _ in range(rows_count)]
    visited = [[False] * width for _ in range(rows_count)]
    
    directions_clockwise = [(0, -1), (1, 0), (0, 1), (-1, 0)]
    directions_counterclockwise = [(0, 1), (1, 0), (0, -1), (-1, 0)]
    
    directions = directions_clockwise if direction == 'clockwise' else directions_counterclockwise
    
    r, c = 0, width - 1
    dir_idx = 0
    remaining = rows_count * width
    text_idx = 0
    
    while remaining > 0 and text_idx < len(text):
        grid[r][c] = text[text_idx]
        visited[r][c] = True
        text_idx += 1
        remaining -= 1
        
        # Bir sonraki adımı dene
        dr, dc = directions[dir_idx]
        nr, nc = r + dr, c + dc
        
        if nr < 0 or nr >= rows_count or nc < 0 or nc >= width or visited[nr][nc]:
            dir_idx = (dir_idx + 1) % 4
            dr, dc = directions[dir_idx]
            nr, nc = r + dr, c + dc
        
        r, c = nr, nc
    
    # Grid'den metni satır satır oku
    result = []
    for row in grid:
        result.extend(row)
    
    decrypted = ''.join(result)
    
    # Sonundaki fill_char karakterlerini kaldır
    while decrypted and decrypted[-1] == fill_char:
        decrypted = decrypted[:-1]
    
    return decrypted


# --- 7. Columnar Transposition Cipher ---
def columnar_encrypt(text, key, fill_char='*'):
    """
    Columnar Transposition (Sütunlu Kaydırma) - Anahtar ile kolon sıralaması
    
    Args:
        text: Şifrelenecek metin
        key: Kolonları sıralamak için anahtar (örn: "truva")
        fill_char: Boşlukları doldurmak için kullanılacak karakter (default: '*')
    
    Returns:
        Şifrelenmiş metin
    """
    # Metni temizle ve büyük harfe çevir
    clean_text = ''.join(text.split()).upper()
    key = key.upper()
    
    if not key or not clean_text:
        return clean_text
    
    # Anahtarın karakterlerini sırala ve numaralandır (alfabetik sıra)
    key_chars = list(key)
    # Aynı karakterler için indeks farkı oluştur (ilk karşılaşılan daha küçük numara alır)
    sorted_chars = sorted(enumerate(key_chars), key=lambda x: (x[1], x[0]))
    
    # Kolon numaralarını oluştur (1'den başlayarak)
    column_order = [0] * len(key)
    for i, (orig_idx, char) in enumerate(sorted_chars):
        column_order[orig_idx] = i + 1
    
    # Grid'i oluştur
    cols = len(key)
    rows = (len(clean_text) + cols - 1) // cols  # Yuvarlama yukarı
    
    # Grid'i doldur
    grid = []
    text_idx = 0
    for i in range(rows):
        row = []
        for j in range(cols):
            if text_idx < len(clean_text):
                row.append(clean_text[text_idx])
                text_idx += 1
            else:
                row.append(fill_char)
        grid.append(row)
    
    # Kolonları sıralı numarasına göre oku
    result = []
    for order in range(1, cols + 1):
        col_idx = column_order.index(order)
        for row in grid:
            result.append(row[col_idx])
    
    return ''.join(result)


def columnar_decrypt(text, key, fill_char='*'):
    """
    Columnar Transposition ile şifrelenmiş metni çözer
    
    Args:
        text: Şifrelenmiş metin
        key: Şifreleme sırasında kullanılan anahtar
        fill_char: Boşlukları doldurmak için kullanılan karakter
    
    Returns:
        Çözülmüş metin
    """
    text = text.upper()
    key = key.upper()
    
    if not key or not text:
        return text
    
    # Anahtarın kolon sıralamasını belirle
    key_chars = list(key)
    sorted_chars = sorted(enumerate(key_chars), key=lambda x: (x[1], x[0]))
    
    column_order = [0] * len(key)
    for i, (orig_idx, char) in enumerate(sorted_chars):
        column_order[orig_idx] = i + 1
    
    # Grid boyutlarını hesapla
    cols = len(key)
    rows = (len(text) + cols - 1) // cols
    total_cells = rows * cols
    
    # Grid'i oluştur
    grid = [[''] * cols for _ in range(rows)]
    
    # Şifrelenmiş metni grid'e yerleştir (kolon sırasına göre)
    text_idx = 0
    for order in range(1, cols + 1):
        col_idx = column_order.index(order)
        for row_idx in range(rows):
            if text_idx < len(text):
                grid[row_idx][col_idx] = text[text_idx]
                text_idx += 1
    
    # Grid'den metni oku (satır satır)
    result = []
    for row in grid:
        result.extend(row)
    
    decrypted = ''.join(result)
    
    # Sonundaki fill_char karakterlerini kaldır
    while decrypted and decrypted[-1] == fill_char:
        decrypted = decrypted[:-1]
    
    return decrypted


# --- 8. Polybius Cipher ---
def polybius_encrypt(text, separator=''):
    """
    Polybius Cipher - Her harfi satır ve sütun numarasına dönüştürür
    
    Args:
        text: Şifrelenecek metin
        separator: Sayılar arası ayırıcı karakter (default: '', örn: '-' veya ' ')
    
    Returns:
        Şifrelenmiş metin (sayı dizisi)
    """
    # Polybius Square: 5x5 grid
    # i ve j aynı hücrede (2,4)
    polybius_square = {
        'A': '11', 'B': '12', 'C': '13', 'D': '14', 'E': '15',
        'F': '21', 'G': '22', 'H': '23', 'I': '24', 'J': '24',
        'K': '25', 'L': '31', 'M': '32', 'N': '33', 'O': '34',
        'P': '35', 'Q': '41', 'R': '42', 'S': '43', 'T': '44',
        'U': '45', 'V': '51', 'W': '52', 'X': '53', 'Y': '54',
        'Z': '55'
    }
    
    text = text.upper()
    result = []
    
    for char in text:
        if char.isalpha():
            result.append(polybius_square.get(char, ''))
        elif char == ' ':
            continue  # Boşlukları atla
        else:
            # Diğer karakterleri koru (opsiyonel)
            continue
    
    return separator.join(result)


def polybius_decrypt(text, separator=''):
    """
    Polybius Cipher ile şifrelenmiş metni çözer
    
    Args:
        text: Şifrelenmiş metin (sayı dizisi)
        separator: Sayılar arası ayırıcı karakter (aynı olmalı)
    
    Returns:
        Çözülmüş metin
    """
    # Polybius Square'in tersi
    inverse_polybius = {
        '11': 'A', '12': 'B', '13': 'C', '14': 'D', '15': 'E',
        '21': 'F', '22': 'G', '23': 'H', '24': 'I',  # I ve J aynı
        '25': 'K', '31': 'L', '32': 'M', '33': 'N', '34': 'O',
        '35': 'P', '41': 'Q', '42': 'R', '43': 'S', '44': 'T',
        '45': 'U', '51': 'V', '52': 'W', '53': 'X', '54': 'Y',
        '55': 'Z'
    }
    
    result = []
    
    # Ayırıcı varsa böl, yoksa her 2 karakteri al
    if separator:
        numbers = text.split(separator)
    else:
        numbers = [text[i:i+2] for i in range(0, len(text), 2)]
    
    for num in numbers:
        # Sadece sayı olanları çöz
        if num.isdigit() and len(num) == 2:
            letter = inverse_polybius.get(num, '')
            if letter:
                result.append(letter)
    
    return ''.join(result)


# --- 9. Pigpen Cipher ---
def pigpen_encrypt(text):
    """

    
    Args:
        text: Şifrelenecek metin
    
    Returns:
        Şifrelenmiş metin (sembol dizisi)
    """
    # Pigpen sembolleri: her harf için benzersiz ASCII tabanlı sembol
    pigpen_symbols = {
        # Grid 1 (3x3 Kare)
        'A': 'L',   # Sol ve üst köşe
        'B': 'R',   # Sağ ve üst köşe
        'C': 'BL',  # Sol ve alt köşe
        'D': 'BR',  # Sağ ve alt köşe
        'E': 'T',   # Üst kenar
        'F': 'B',   # Alt kenar
        'G': 'LS',  # Sol kenar
        'H': 'RS',  # Sağ kenar
        'I': 'S',   # Tam kare
        
        # Grid 2 (3x3 Kare + nokta)
        'J': 'L.',  # Sol ve üst köşe + nokta
        'K': 'R.',  # Sağ ve üst köşe + nokta
        'L': 'BL.', # Sol ve alt köşe + nokta
        'M': 'BR.', # Sağ ve alt köşe + nokta
        'N': 'T.',  # Üst kenar + nokta
        'O': 'B.',  # Alt kenar + nokta
        'P': 'LS.', # Sol kenar + nokta
        'Q': 'RS.', # Sağ kenar + nokta
        'R': 'S.',  # Tam kare + nokta
        
        # Grid 3 (X şekli)
        'S': '/',   # Sol üst X
        'T': '\\',  # Sağ üst X
        'U': 'LU',  # Sol alt X
        'V': 'RU',  # Sağ alt X
        
        # Grid 4 (X + nokta)
        'W': '/.',  # Sol üst X + nokta
        'X': '\\.', # Sağ üst X + nokta
        'Y': 'LU.', # Sol alt X + nokta
        'Z': 'RU.', # Sağ alt X + nokta
    }
    
    text = text.upper()
    result = []
    
    for char in text:
        if char.isalpha():
            symbol = pigpen_symbols.get(char, char)
            result.append(symbol)
        elif char == ' ':
            result.append(' ')
        else:
            result.append(char)
    
    return ''.join(result)


def pigpen_decrypt(text):
    """
    Pigpen Cipher ile şifrelenmiş metni çözer
    
    Args:
        text: Şifrelenmiş metin (sembol dizisi)
    
    Returns:
        Çözülmüş metin
    """
    # Pigpen sembollerinden harfe dönüştürme (ASCII tabanlı)
    symbol_to_letter = {
        'L': 'A', 'R': 'B', 'BL': 'C', 'BR': 'D', 'T': 'E',
        'B': 'F', 'LS': 'G', 'RS': 'H', 'S': 'I',
        'L.': 'J', 'R.': 'K', 'BL.': 'L', 'BR.': 'M', 'T.': 'N',
        'B.': 'O', 'LS.': 'P', 'RS.': 'Q', 'S.': 'R',
        '/': 'S', '\\': 'T', 'LU': 'U', 'RU': 'V',
        '/.': 'W', '\\.': 'X', 'LU.': 'Y', 'RU.': 'Z',
    }
    
    result = []
    i = 0
    
    while i < len(text):
        char = text[i]
        
        if char == ' ':
            result.append(' ')
            i += 1
            continue
        
        # 1-5 karakterlik sembolleri kontrol et
        found = False
        for length in range(5, 0, -1):
            if i + length <= len(text):
                symbol = text[i:i+length]
                if symbol in symbol_to_letter:
                    result.append(symbol_to_letter[symbol])
                    i += length
                    found = True
                    break
        
        if not found:
            # Sembol bulunamadı, orijinal karakteri koru
            result.append(char)
            i += 1
    
    return ''.join(result)



# --- Key validation helpers (ASSIGNMENT REQUIREMENTS) ---
def _require_exact_len_str(key: str, n: int, algo_name: str) -> str:
    if key is None:
        raise ValueError(f"{algo_name} için anahtar zorunludur.")
    if len(key) != n:
        raise ValueError(f"{algo_name} anahtarı tam olarak {n} byte/karakter olmalıdır.")
    return key

def _require_exact_len_bytes(key: bytes, n: int, algo_name: str) -> bytes:
    if key is None:
        raise ValueError(f"{algo_name} için anahtar zorunludur.")
    if len(key) != n:
        raise ValueError(f"{algo_name} anahtarı tam olarak {n} byte olmalıdır.")
    return key

# --- 10. Hill Cipher ---
def _clean_text_to_numbers(text):
    """Metni A=0..Z=25 sayısına çevirir, harf olmayanları atar."""
    return [ord(ch) - ord('A') for ch in text.upper() if ch.isalpha()]


def _chunk(lst, size, fill_value=23):
    """
    listedeki elemanları bloklara böler; eksik kalanları fill_value (X=23) ile doldurur
    fill_value default olarak 'X' karşılığı 23'tür.
    """
    padded = list(lst)
    while len(padded) % size != 0:
        padded.append(fill_value)
    for i in range(0, len(padded), size):
        yield padded[i:i + size]


def _mat_identity(n):
    return [[1 if i == j else 0 for j in range(n)] for i in range(n)]


def _mat_mod_inv(matrix, mod=26):
    """
    Kare matrisin modüler tersini Gauss-Jordan ile hesaplar.
    Matris terslenemezse ValueError fırlatır.
    """
    n = len(matrix)
    # Augment with identity
    aug = [row[:] + ident_row[:] for row, ident_row in zip(matrix, _mat_identity(n))]

    for col in range(n):
        pivot = None
        for r in range(col, n):
            val = aug[r][col] % mod
            if val == 0:
                continue
            try:
                pow(val, -1, mod)
                pivot = r
                break
            except ValueError:
                continue
        if pivot is None:
            raise ValueError("Anahtar matrisi mod 26'da terslenebilir olmalı.")
        # swap
        aug[col], aug[pivot] = aug[pivot], aug[col]
        inv_pivot = pow(aug[col][col], -1, mod)
        aug[col] = [(x * inv_pivot) % mod for x in aug[col]]
        for r in range(n):
            if r == col:
                continue
            factor = aug[r][col] % mod
            if factor == 0:
                continue
            aug[r] = [(a - factor * b) % mod for a, b in zip(aug[r], aug[col])]

    # Extract inverse
    return [row[n:] for row in aug]


def _mat_vec_mul(matrix, vector, mod=26):
    return [sum(a * b for a, b in zip(row, vector)) % mod for row in matrix]


def _numbers_to_text(nums):
    return ''.join(chr(n + ord('A')) for n in nums)


def hill_encrypt(text, key_matrix):
    """
    Hill Cipher ile şifreleme.
    key_matrix kare ve mod 26'da terslenebilir olmalıdır.
    Harf olmayan karakterler atılır; eksik bloklar 'X' ile doldurulur.
    """
    size = len(key_matrix)
    numbers = _clean_text_to_numbers(text)
    result = []
    for block in _chunk(numbers, size):
        enc_block = _mat_vec_mul(key_matrix, block)
        result.extend(enc_block)
    return _numbers_to_text(result)


def hill_decrypt(text, key_matrix):
    """
    Hill Cipher ile deşifreleme.
    key_matrix kare ve mod 26'da terslenebilir olmalıdır.
    """
    size = len(key_matrix)
    inv_key = _mat_mod_inv(key_matrix, mod=26)
    numbers = _clean_text_to_numbers(text)
    result = []
    for block in _chunk(numbers, size):
        dec_block = _mat_vec_mul(inv_key, block)
        result.extend(dec_block)
    return _numbers_to_text(result)


# --- 11. DES (Data Encryption Standard) ---

# DES Permutation Tables
# Initial Permutation (IP)
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# Final Permutation (IP^-1)
FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

# Expansion Permutation (E)
E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

# Permutation (P)
P = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
]

# PC-1 (Key Permutation Choice 1)
PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

# PC-2 (Key Permutation Choice 2)
PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

# Left shifts for each round
SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# S-boxes
S_BOXES = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]


def _permute(bits, table):
    """Permütasyon tablosuna göre bitleri yeniden düzenler"""
    return [bits[i - 1] for i in table]


def _left_shift(bits, n):
    """Bitleri n pozisyon sola kaydırır"""
    return bits[n:] + bits[:n]


def _xor(bits1, bits2):
    """İki bit dizisini XOR işlemine tabi tutar"""
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]


def _s_box_substitution(bits):
    """S-box yerine koyma işlemi"""
    result = []
    for i in range(8):
        block = bits[i * 6:(i + 1) * 6]
        row = block[0] * 2 + block[5]
        col = block[1] * 8 + block[2] * 4 + block[3] * 2 + block[4]
        value = S_BOXES[i][row][col]
        result.extend([(value >> 3) & 1, (value >> 2) & 1, (value >> 1) & 1, value & 1])
    return result


def _f_function(right, round_key):
    """DES'in f fonksiyonu"""
    # Expansion
    expanded = _permute(right, E)
    # XOR with round key
    xored = _xor(expanded, round_key)
    # S-box substitution
    substituted = _s_box_substitution(xored)
    # Permutation
    return _permute(substituted, P)


def _generate_round_keys(key_bits):
    """16 round için anahtarları üretir"""
    # PC-1 permütasyonu
    key_56 = _permute(key_bits, PC1)
    
    # C ve D'ye böl
    C = key_56[:28]
    D = key_56[28:]
    
    round_keys = []
    for shift in SHIFTS:
        C = _left_shift(C, shift)
        D = _left_shift(D, shift)
        # C ve D'yi birleştir
        CD = C + D
        # PC-2 permütasyonu
        round_key = _permute(CD, PC2)
        round_keys.append(round_key)
    
    return round_keys


def _text_to_bits(text):
    """Metni bit dizisine çevirir (8 bit per karakter)"""
    bits = []
    for char in text:
        byte = ord(char)
        bits.extend([(byte >> i) & 1 for i in range(7, -1, -1)])
    return bits


def _bits_to_text(bits):
    """Bit dizisini metne çevirir"""
    text = []
    for i in range(0, len(bits), 8):
        byte_bits = bits[i:i + 8]
        if len(byte_bits) < 8:
            byte_bits = byte_bits + [0] * (8 - len(byte_bits))
        byte = sum(bit << (7 - j) for j, bit in enumerate(byte_bits))
        text.append(chr(byte))
    return ''.join(text)


def _pad_text(text, block_size=8):
    """Metni 8 byte (64 bit) bloklara böler ve eksikleri doldurur"""
    padding = block_size - (len(text) % block_size)
    return text + chr(padding) * padding


def _unpad_text(text):
    """Padding'i kaldırır"""
    if not text:
        return text
    padding = ord(text[-1])
    if padding > len(text):
        return text
    return text[:-padding]


def des_encrypt(text, key):
    """
    DES şifreleme
    
    Args:
        text: Şifrelenecek metin
        key: 8 karakterlik anahtar (64 bit, her 8. bit parity)
    
    Returns:
        Şifrelenmiş metin (hex formatında)
    """
    # Anahtarı 8 karaktere tamamla
    key = _require_exact_len_str(key, 8, 'DES (Manual)')
    
    # Anahtarı bit dizisine çevir
    key_bits = _text_to_bits(key)
    
    # Round anahtarlarını üret
    round_keys = _generate_round_keys(key_bits)
    
    # Metni padding ile doldur
    padded_text = _pad_text(text)
    
    encrypted_blocks = []
    
    # Her 8 byte'lık blok için
    for i in range(0, len(padded_text), 8):
        block = padded_text[i:i + 8]
        block_bits = _text_to_bits(block)
        
        # Initial Permutation
        permuted = _permute(block_bits, IP)
        
        # L ve R'ye böl
        L = permuted[:32]
        R = permuted[32:]
        
        # 16 round
        for round_key in round_keys:
            new_R = _xor(L, _f_function(R, round_key))
            L = R
            R = new_R
        
        # Son swap (16. round'dan sonra)
        L, R = R, L
        
        # Birleştir
        combined = L + R
        
        # Final Permutation
        encrypted_bits = _permute(combined, FP)
        
        # Bitleri byte'lara çevir ve hex'e dönüştür
        encrypted_bytes = []
        for j in range(0, len(encrypted_bits), 8):
            byte_bits = encrypted_bits[j:j + 8]
            byte = sum(bit << (7 - k) for k, bit in enumerate(byte_bits))
            encrypted_bytes.append(byte)
        
        encrypted_blocks.append(''.join(f'{b:02x}' for b in encrypted_bytes))
    
    return ''.join(encrypted_blocks)


def des_decrypt(ciphertext_hex, key):
    """
    DES deşifreleme
    
    Args:
        ciphertext_hex: Hex formatında şifrelenmiş metin
        key: 8 karakterlik anahtar (şifreleme ile aynı)
    
    Returns:
        Çözülmüş metin
    """
    # Anahtarı 8 karaktere tamamla
    key = _require_exact_len_str(key, 8, 'DES (Manual)')
    
    # Anahtarı bit dizisine çevir
    key_bits = _text_to_bits(key)
    
    # Round anahtarlarını üret
    round_keys = _generate_round_keys(key_bits)
    
    # Round anahtarlarını ters çevir (deşifreleme için)
    round_keys = round_keys[::-1]
    
    decrypted_blocks = []
    
    # Hex'i byte'lara çevir
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)
    
    # Her 8 byte'lık blok için
    for i in range(0, len(ciphertext_bytes), 8):
        block_bytes = ciphertext_bytes[i:i + 8]
        if len(block_bytes) < 8:
            block_bytes = block_bytes + b'\0' * (8 - len(block_bytes))
        
        block_bits = []
        for byte in block_bytes:
            block_bits.extend([(byte >> j) & 1 for j in range(7, -1, -1)])
        
        # Initial Permutation
        permuted = _permute(block_bits, IP)
        
        # L ve R'ye böl
        L = permuted[:32]
        R = permuted[32:]
        
        # 16 round (ters sırada anahtarlarla)
        for round_key in round_keys:
            new_R = _xor(L, _f_function(R, round_key))
            L = R
            R = new_R
        
        # Son swap
        L, R = R, L
        
        # Birleştir
        combined = L + R
        
        # Final Permutation
        decrypted_bits = _permute(combined, FP)
        
        # Bitleri metne çevir
        decrypted_text = _bits_to_text(decrypted_bits)
        decrypted_blocks.append(decrypted_text)
    
    # Tüm blokları birleştir ve padding'i kaldır
    result = ''.join(decrypted_blocks)
    return _unpad_text(result)

def _derive_aes_key(key: str) -> bytes:
    """
    Kullanıcının girdiği anahtardan 16 byte AES anahtarı üretir
    """
    h = SHA256.new(key.encode("utf-8")).digest()
    return h[:16]  # AES-128


def aes_user_encrypt(plaintext: str, key: str) -> str:
    key = _require_exact_len_str(key, 16, 'AES')
    aes_key = key.encode('utf-8')
    iv = get_random_bytes(16)

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))

    return base64.b64encode(iv + ciphertext).decode("utf-8")


def aes_user_decrypt(ciphertext: str, key: str) -> str:
    raw = base64.b64decode(ciphertext)
    iv = raw[:16]
    data = raw[16:]

    key = _require_exact_len_str(key, 16, 'AES')
    aes_key = key.encode('utf-8')
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)

    plaintext = unpad(cipher.decrypt(data), AES.block_size)
    return plaintext.decode("utf-8")

# --- AES-128 (Library) CBC + Base64 ---
# Not: Bu modda anahtar kullanıcıdan alınmaz; RSA ile (base64 olarak) iletilen 16-byte key kullanılır.
def aes_lib_encrypt(plaintext: str, key_bytes: bytes) -> str:
    k = _require_exact_len_bytes(key_bytes, 16, "AES-128 (Library)")
    iv = get_random_bytes(16)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
    return base64.b64encode(iv + ct).decode("utf-8")

def aes_lib_decrypt(ciphertext_b64: str, key_bytes: bytes) -> str:
    k = _require_exact_len_bytes(key_bytes, 16, "AES-128 (Library)")
    raw = base64.b64decode(ciphertext_b64)
    iv, ct = raw[:16], raw[16:]
    cipher = AES.new(k, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode("utf-8")

# --- DES (Library) CBC + Base64 ---
# Not: Bu modda anahtar kullanıcıdan alınmaz; RSA ile (base64 olarak) iletilen 8-byte key kullanılır.
def des_lib_encrypt(plaintext: str, key_bytes: bytes) -> str:
    k = _require_exact_len_bytes(key_bytes, 8, "DES (Library)")
    iv = get_random_bytes(8)
    cipher = DES.new(k, DES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext.encode("utf-8"), 8))
    return base64.b64encode(iv + ct).decode("utf-8")

def des_lib_decrypt(ciphertext_b64: str, key_bytes: bytes) -> str:
    k = _require_exact_len_bytes(key_bytes, 8, "DES (Library)")
    raw = base64.b64decode(ciphertext_b64)
    iv, ct = raw[:8], raw[8:]
    cipher = DES.new(k, DES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), 8)
    return pt.decode("utf-8")


# --- RSA (Library) OAEP + Base64 ---
def rsa_generate_keypair(bits: int = 2048):
    key = RSA.generate(bits)
    private_pem = key.export_key().decode("utf-8")
    public_pem = key.publickey().export_key().decode("utf-8")
    return public_pem, private_pem

def rsa_encrypt_text(public_pem: str, plaintext: str) -> str:
    pub = RSA.import_key(public_pem.encode("utf-8"))
    cipher = PKCS1_OAEP.new(pub)  # SHA1 default
    ct = cipher.encrypt(plaintext.encode("utf-8"))
    return base64.b64encode(ct).decode("utf-8")

def rsa_decrypt_text(private_pem: str, ciphertext_b64: str) -> str:
    priv = RSA.import_key(private_pem.encode("utf-8"))
    cipher = PKCS1_OAEP.new(priv)
    ct = base64.b64decode(ciphertext_b64)
    pt = cipher.decrypt(ct)
    return pt.decode("utf-8")


# 4-bit S-Box (Mini AES)
S_BOX = {
    0x0: 0xE, 0x1: 0x4, 0x2: 0xD, 0x3: 0x1,
    0x4: 0x2, 0x5: 0xF, 0x6: 0xB, 0x7: 0x8,
    0x8: 0x3, 0x9: 0xA, 0xA: 0x6, 0xB: 0xC,
    0xC: 0x5, 0xD: 0x9, 0xE: 0x0, 0xF: 0x7
}

INV_S_BOX = {v: k for k, v in S_BOX.items()}

def _sub_nibbles(data):
    return bytes((S_BOX[b >> 4] << 4 | S_BOX[b & 0x0F]) for b in data)

def _inv_sub_nibbles(data):
    return bytes((INV_S_BOX[b >> 4] << 4 | INV_S_BOX[b & 0x0F]) for b in data)

def _xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def aes_manual_encrypt(plaintext: str, key: str) -> str:
    """
    Toy AES (2 round, simplified)
    """
    key = _require_exact_len_str(key, 16, 'AES (Manual)')
    data = plaintext.encode("utf-8")
    key_bytes = key.encode("utf-8").ljust(len(data), b"\0")

    # Round 1
    state = _xor_bytes(data, key_bytes)
    state = _sub_nibbles(state)

    # Round 2
    state = _xor_bytes(state, key_bytes)
    state = _sub_nibbles(state)

    return base64.b64encode(state).decode("utf-8")

def aes_manual_decrypt(ciphertext_b64: str, key: str) -> str:
    key = _require_exact_len_str(key, 16, 'AES (Manual)')
    data = base64.b64decode(ciphertext_b64)
    key_bytes = key.encode("utf-8").ljust(len(data), b"\0")

    # Inverse Round 2
    state = _inv_sub_nibbles(data)
    state = _xor_bytes(state, key_bytes)

    # Inverse Round 1
    state = _inv_sub_nibbles(state)
    state = _xor_bytes(state, key_bytes)

    return state.decode("utf-8", errors="ignore")
