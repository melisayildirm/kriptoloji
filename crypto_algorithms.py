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
    Pigpen Cipher - Mason şifresi, harfleri sembollere dönüştürür
    
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