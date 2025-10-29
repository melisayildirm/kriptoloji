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