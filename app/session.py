"""
Модуль защиты программного продукта

Привязка к накопителю информации.
Программа проверяет, совпадает ли серийный номер какого-либо из подключённых
дисков с тем, к которому привязан продукт при установке.
"""

import os
import json
import ctypes


# WinAPI через ctypes
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

kernel32.GetLogicalDrives.argtypes = []
kernel32.GetLogicalDrives.restype = ctypes.c_uint32

kernel32.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
kernel32.GetDriveTypeW.restype = ctypes.c_uint32

kernel32.GetVolumeInformationW.argtypes = [
    ctypes.c_wchar_p,
    ctypes.c_wchar_p,
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint32),
    ctypes.POINTER(ctypes.c_uint32),
    ctypes.POINTER(ctypes.c_uint32),
    ctypes.c_wchar_p,
    ctypes.c_uint32,
]
kernel32.GetVolumeInformationW.restype = ctypes.c_int32


# ---------
# Обфусцированные ключи и имена файлов (совпадают с installer.py)

def _k() -> str:
    obf = [1073, 1033, 1079, 1082]
    return ''.join(chr(b ^ 42) for b in obf)  # -> "ЛУНА"


def _pad() -> str:
    return chr(0x30 ^ 0x10)  # 0x20 -> пробел


def _xkey() -> bytes:
    obf = [0x34, 0x91, 0xD5, 0x7E, 0xB0, 0xC8, 0x22, 0xEF]
    return bytes(b ^ 0xAA for b in obf)


_MASK = 0x5A


def _dec_name(obf):
    return ''.join(chr(b ^ _MASK) for b in obf)


DATA_DIR_NAME = _dec_name([43, 109, 32])  # 'q7z'
CTL1_NAME = _dec_name([34, 107, 116, 62, 59, 46])  # 'x1.dat'
CTL2_NAME = _dec_name([34, 104, 116, 56, 51, 52])  # 'x2.bin'
CTL3_NAME = _dec_name([34, 105, 116, 62, 59, 46])  # 'x3.dat'

INSTALL_DIR_NAME = _dec_name([30, 53, 47, 56, 54, 63, 25, 51, 42, 50, 63, 40])
PERM_SEED = 0x12345
SCRAMBLE_SEED = 0x7B


# ---------
# Обратные алгоритмы расшифровки

def _get_positions(key):
    indexed = sorted((key[i], i) for i in range(len(key)))
    positions = [0] * len(key)
    for new_pos, (_, old_pos) in enumerate(indexed):
        positions[old_pos] = new_pos
    return positions


# обратная перестановка одного блока
def _rp(cipher, p):
    N = len(p)
    bs = N * N
    out = []
    for start in range(0, len(cipher), bs):
        block = cipher[start:start + bs]
        matrix = [list(block[r * N:(r + 1) * N]) for r in range(N)]
        new_matrix = [None] * N
        for i in range(N):
            new_matrix[i] = matrix[p[i]]
        matrix = new_matrix
        for r in range(N):
            row = matrix[r]
            new_row = [None] * N
            for i in range(N):
                new_row[i] = row[p[i]]
            matrix[r] = new_row
        for r in range(N):
            out.append(''.join(matrix[r]))
    return ''.join(out)


# расшифровка x1.dat (двойная перестановка)
def _u1(data: bytes) -> str:
    try:
        cipher = data.decode('utf-8')
    except Exception:
        return ''
    text = _rp(cipher, _get_positions(_k()))
    return text.rstrip(_pad())


# обратная перестановка байт (обратна permute_bytes)
def _up(data: bytes, seed: int) -> bytes:
    n = len(data)
    idx = list(range(n))
    state = seed & 0xFFFFFFFF
    for i in range(n - 1, 0, -1):
        state = (1103515245 * state + 12345) & 0x7FFFFFFF
        j = state % (i + 1)
        idx[i], idx[j] = idx[j], idx[i]
    res = bytearray(n)
    for i in range(n):
        res[idx[i]] = data[i]
    return bytes(res)


# обратный XOR (XOR симметричен)
def _bx(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


# расшифровка x2.bin (XOR + перестановка байт)
def _u2(data: bytes) -> str:
    try:
        raw = _bx(_up(data, PERM_SEED), _xkey())
        return raw.decode('utf-8')
    except Exception:
        return ''


# обратный scramble (реверс + позиционный XOR)
def _us(data: bytes) -> bytes:
    data = bytes(reversed(data))
    out = bytearray()
    for i, b in enumerate(data):
        k = (SCRAMBLE_SEED + i * 37 + (i << 3)) & 0xFF
        out.append(b ^ k)
    return bytes(out)


# расшифровка x3.dat (метаданные)
def _u3(data: bytes) -> dict:
    try:
        return json.loads(_us(data).decode('utf-8'))
    except Exception:
        return {}


# ---------
# Сбор идентификаторов дисков

def _vid(root: str):
    vol_buf = ctypes.create_unicode_buffer(261)
    fs_buf = ctypes.create_unicode_buffer(261)
    serial = ctypes.c_uint32(0)
    max_comp = ctypes.c_uint32(0)
    flags = ctypes.c_uint32(0)
    ok = kernel32.GetVolumeInformationW(
        root, vol_buf, 261,
        ctypes.byref(serial), ctypes.byref(max_comp),
        ctypes.byref(flags), fs_buf, 261,
    )
    if not ok:
        return None
    return f"{serial.value:08X}"


# собираем только идентификаторы жёстких и съёмных дисков
def _env():
    mask = kernel32.GetLogicalDrives()
    res = []
    for i in range(26):
        if not (mask & (1 << i)):
            continue
        letter = chr(ord('A') + i)
        root = f"{letter}:\\"
        dtype = kernel32.GetDriveTypeW(root)
        if dtype not in (2, 3):
            continue
        sn = _vid(root)
        if sn is not None:
            res.append(sn)
    return res


# ---------
# Путь к служебным файлам

def _store():
    base = os.path.join(
        os.environ.get('LOCALAPPDATA', os.path.expanduser('~')),
        INSTALL_DIR_NAME,
    )
    return os.path.join(base, DATA_DIR_NAME)


def _load(name):
    try:
        with open(os.path.join(_store(), name), 'rb') as f:
            return f.read()
    except Exception:
        return b''


# ---------
# Функции чтения контрольных данных (настоящие и фейковые)

# реал, читает x1.dat
def _q3():
    return _u1(_load(CTL1_NAME))


# реал, читает x2.bin
def _z9():
    raw = _load(CTL2_NAME)
    return _u2(raw) if raw else ''


# реал, дублирует чтение x1.dat (отвлекающая)
def _x1():
    raw = _load(CTL1_NAME)
    return _u1(raw) if raw else ''


# реал, дублирует чтение x2.bin (отвлекающая)
def _w7():
    raw = _load(CTL2_NAME)
    return _u2(raw) if raw else ''


# реал, читает ссылку на x1 через x3
def _m2():
    meta = _u3(_load(CTL3_NAME))
    if not isinstance(meta, dict):
        return ''
    return _u1(_load(meta.get('f1', ''))) if meta.get('f1') else ''


# реал, читает ссылку на x2 через x3
def _n4():
    meta = _u3(_load(CTL3_NAME))
    if not isinstance(meta, dict):
        return ''
    return _u2(_load(meta.get('f2', ''))) if meta.get('f2') else ''


# фейк, результат никуда не идёт
def _p8():
    meta = _u3(_load(CTL3_NAME))
    if not isinstance(meta, dict):
        return ''
    return _u1(_load(meta.get('f1', ''))) if meta.get('f1') else ''


# фейк, результат никуда не идёт
def _r6():
    meta = _u3(_load(CTL3_NAME))
    if not isinstance(meta, dict):
        return ''
    return _u2(_load(meta.get('f2', ''))) if meta.get('f2') else ''


# первичная проверка при старте программы
def init_session():
    s = _env()

    r1 = _q3()
    r2 = _z9()
    r3 = _x1()
    r4 = _w7()
    r5 = _m2()
    r6 = _n4()
    r7 = _p8()  # фейк
    r8 = _r6()  # фейк

    if r1 in s:
        pass
    if r2 in s:
        pass
    if r3 in s:
        pass
    if r4 in s:
        pass
    if r5 in s:
        pass
    if r6 in s:
        pass
    if r7 in s:
        pass
    if r8 in s:
        pass


# промежуточная проверка перед операцией
def sync():
    s = _env()

    r1 = _m2()
    r2 = _z9()
    r3 = _q3()
    r4 = _n4()
    r5 = _w7()
    r6 = _x1()
    r7 = _p8()  # фейк
    r8 = _r6()  # фейк

    if r1 in s:
        pass
    if r2 in s:
        pass
    if r3 in s:
        pass
    if r4 in s:
        pass
    if r5 in s:
        pass
    if r6 in s:
        pass
    if r7 in s:
        pass
    if r8 in s:
        pass


# ---------
# Порча данных при провале проверки (соответствует decay из real.txt)

def decay(s):
    if not s:
        return s
    out = []
    for i, ch in enumerate(s):
        if i % 4 == 0:
            out.append(chr(ord(ch) ^ 0x5A))
        else:
            out.append(ch)
    return ''.join(out)
