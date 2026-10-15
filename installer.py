"""
Установщик защищённой программы с привязкой к накопителю информации

Запускается с флешки. Определяет доступные логические диски,
позволяет пользователю выбрать диск для привязки, копирует
защищаемую программу в папку пользователя и создаёт
зашифрованные контрольные файлы с информацией о накопителе
"""

import os
import sys
import ctypes
import shutil
import json
import tkinter as tk
from tkinter import ttk, messagebox
from math import gcd


# WinAPI через ctypes
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# настройка геттеров
kernel32.GetLogicalDrives.argtypes = []  # список типов аргументов по порядку (тут их нет)
kernel32.GetLogicalDrives.restype = ctypes.c_uint32  # тип возвращаемого значения

kernel32.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
kernel32.GetDriveTypeW.restype = ctypes.c_uint32

kernel32.GetVolumeInformationW.argtypes = [
    ctypes.c_wchar_p,                    # lpRootPathName
    ctypes.c_wchar_p,                    # lpVolumeNameBuffer
    ctypes.c_uint32,                     # nVolumeNameSize
    ctypes.POINTER(ctypes.c_uint32),     # lpVolumeSerialNumber
    ctypes.POINTER(ctypes.c_uint32),     # lpMaximumComponentLength
    ctypes.POINTER(ctypes.c_uint32),     # lpFileSystemFlags
    ctypes.c_wchar_p,                    # lpFileSystemNameBuffer
    ctypes.c_uint32,                     # nFileSystemNameSize
]
kernel32.GetVolumeInformationW.restype = ctypes.c_bool

DRIVE_TYPE_NAMES = {
    0: "Unknown",
    1: "No root",
    2: "Съёмный (флешка)",
    3: "Жёсткий диск",
    4: "Сетевой",
    5: "CD-ROM",
    6: "RAM-диск",
}


# информация о томе (например, о C:\)
def get_volume_info(root: str) -> dict | None:
    vol_buf = ctypes.create_unicode_buffer(261)
    fs_buf = ctypes.create_unicode_buffer(261)
    serial = ctypes.c_uint32(0)
    max_comp = ctypes.c_uint32(0)
    flags = ctypes.c_uint32(0)
    ok = kernel32.GetVolumeInformationW(
        root,
        vol_buf, 261,
        ctypes.byref(serial),
        ctypes.byref(max_comp),
        ctypes.byref(flags),
        fs_buf, 261,
    )
    if not ok:
        return None
    return {
        'volume': vol_buf.value,  # метка тома
        'serial': f"{serial.value:08X}",  # серийный номер
        'fs': fs_buf.value,  # файловая система (FAT32, ...)
    }


# список всех доступных дисков
def list_drives() -> list[dict]:
    # вида 0b0..00000100, бит диска C = 1 значит доступен
    mask = kernel32.GetLogicalDrives()

    result = []
    for i in range(26):  # от A до Z
        if not (mask & (1 << i)):
            continue
        letter = chr(ord('A') + i)
        root = f"{letter}:\\"
        dtype = kernel32.GetDriveTypeW(root)  # узнаем тип диска
        if dtype not in (2, 3):  # оставляем только съёмные и жёсткие
            continue
        info = get_volume_info(root)
        if info is None:
            continue
        result.append({
            'root': root,
            'type': DRIVE_TYPE_NAMES.get(dtype),
            'drive_type': dtype,
            **info,  # распаковка ключей словаря в новый словарь
        })
    return result


# ---------
# Обфусцированные ключи и имена файлов (такие же в защищённой программе)
def _k() -> str:
    # ключ для двойной перестановки
    obf = [1073, 1033, 1079, 1082]
    return ''.join(chr(b ^ 42) for b in obf)  # -> "ЛУНА"


def _pad() -> str:
    # pad char для двойной перестановки
    return chr(0x30 ^ 0x10)   # 0x20 -> пробел (чтобы не читалось очевидно)


def _xkey() -> bytes:
    # ключ XOR
    obf = [0x34, 0x91, 0xD5, 0x7E, 0xB0, 0xC8, 0x22, 0xEF]
    return bytes(b ^ 0xAA for b in obf)


_MASK = 0x5A  # 90


def _dec_name(obf):
    # восстановление имени файла из обфусцированного массива
    return ''.join(chr(b ^ _MASK) for b in obf)


DATA_DIR_NAME = _dec_name([43, 109, 32])  # 'q7z', папка с контрольными файлами
CTL1_NAME = _dec_name([34, 107, 116, 62, 59, 46])  # 'x1.dat'
CTL2_NAME = _dec_name([34, 104, 116, 56, 51, 52])  # 'x2.bin'
CTL3_NAME = _dec_name([34, 105, 116, 62, 59, 46])  # 'x3.dat'

INSTALL_DIR_NAME = 'DoubleCipher'  # имя папки установки в %LOCALAPPDATA%
PERM_SEED = 0x12345  # сид перестановки байт
SCRAMBLE_SEED = 0x7B  # сид для третьего метода


# ----------
# Шифрование двойной перестановкой (1)
def _get_positions(key: str):
    # позиции символов ключа для перестановки
    indexed = sorted((key[i], i) for i in range(len(key)))
    positions = [0] * len(key)
    for new_pos, (_, old_pos) in enumerate(indexed):
        positions[old_pos] = new_pos
    return positions


def _pad_text(text: str, N1: int, N2: int, pad_char: str):
    bs1, bs2 = N1 * N1, N2 * N2
    step = bs1 * bs2 // gcd(bs1, bs2)
    if len(text) % step:
        text += pad_char * (step - len(text) % step)
    return text


def encrypt(text: str, key: str, pad_char=_pad()):
    # дополняем текст до нужной длины
    text = _pad_text(text, len(key), len(key), pad_char)
    # получаем позиции для перестановки по ключу
    p = _get_positions(key)
    N = len(p)
    bs = N * N
    out = []
    for start in range(0, len(text), bs):
        block = text[start:start + bs]
        matrix = [list(block[r * N:(r + 1) * N]) for r in range(N)]
        # 1) перестановка столбцов
        for r in range(N):
            row = matrix[r]
            new_row = [None] * N
            for i in range(N):
                new_row[p[i]] = row[i]
            matrix[r] = new_row
        # 2) перестановка строк
        new_matrix = [None] * N
        for i in range(N):
            new_matrix[p[i]] = matrix[i]
        matrix = new_matrix

        for r in range(N):
            out.append(''.join(matrix[r]))
    return ''.join(out)


# XOR шифрование (2)
def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


# Детерминированная перестановка байт на LCG (Фишер-Йетс)
def permute_bytes(data: bytes, seed: int) -> bytes:
    n = len(data)
    idx = list(range(n))
    state = seed & 0xFFFFFFFF
    for i in range(n - 1, 0, -1):
        state = (1103515245 * state + 12345) & 0x7FFFFFFF
        j = state % (i + 1)
        idx[i], idx[j] = idx[j], idx[i]
    return bytes(data[idx[i]] for i in range(n))


# XOR с позиционно-зависимым ключом + реверс (3)
def scramble(data: bytes) -> bytes:
    out = bytearray()
    for i, b in enumerate(data):
        k = (SCRAMBLE_SEED + i * 37 + (i << 3)) & 0xFF
        out.append(b ^ k)
    return bytes(reversed(out))


# ---------
# Установка

# получение директории откуда исполняемый файл
def get_base_dir() -> str:
    if getattr(sys, 'frozen', False):  # атрибут frozen есть только у exe файла
        return os.path.dirname(sys.executable)  # путь к exe файлу (без самого него)
    return os.path.dirname(os.path.abspath(__file__))  # путь к py файлу (без самого него)


# установка программы с привязкой к выбранному диску
def do_install(target: dict, source_app_dir: str, log):
    install_root = os.path.join(
        # ищем переменную окружения LOCALAPPDATA, иначе берем домашнюю папку юзера
        os.environ.get('LOCALAPPDATA', os.path.expanduser('~')),
        INSTALL_DIR_NAME,
    )
    data_dir = os.path.join(install_root, DATA_DIR_NAME)

    log(f"Папка установки: {install_root}")
    log(f"Привязка к диску: {target['root']} ({target['type']})")
    log(f"Серийный номер: {target['serial']}")

    if not os.path.isdir(source_app_dir):
        raise RuntimeError(
            f"Не найдена папка с программой: {source_app_dir}\n"
            "Убедитесь, что установщик запускается с флешки и рядом с ним есть папка 'app'."
        )

    # удаляем возможную прошлую установку
    if os.path.exists(install_root):
        shutil.rmtree(install_root, ignore_errors=True)
    os.makedirs(data_dir, exist_ok=True)

    log("Копирование файлов программы...")
    copied = 0
    for name in os.listdir(source_app_dir):
        if name in ('__pycache__', '.DS_Store'):
            continue
        src = os.path.join(source_app_dir, name)
        dst = os.path.join(install_root, name)
        try:
            if os.path.isfile(src):
                shutil.copy2(src, dst)
                copied += 1
            elif os.path.isdir(src):
                shutil.copytree(src, dst)
                copied += 1
        except OSError as e:
            shutil.rmtree(install_root, ignore_errors=True)  # откат
            raise RuntimeError(
                f"Ошибка чтения '{name}': {e}\n"
                "Похоже, флешка была извлечена. Установка отменена."
            )
    log(f"Скопировано объектов: {copied}")

    # контрольные данные
    bind_string = target['serial'] + '|' + target['root']  # например 1A2B3C4D|E:\
    # записываем их в скрытую папку data_dir в три файла с разными методами шифрования

    # ctl1: двойная перестановка
    enc1 = encrypt(bind_string, _k())
    with open(os.path.join(data_dir, CTL1_NAME), 'wb') as f:
        f.write(enc1.encode('utf-8'))
    log(f"Создан {CTL1_NAME} (двойная перестановка)")

    # ctl2: XOR + перестановка байт
    raw = bind_string.encode('utf-8')
    enc2 = permute_bytes(xor_bytes(raw, _xkey()), PERM_SEED)
    with open(os.path.join(data_dir, CTL2_NAME), 'wb') as f:
        f.write(enc2)
    log(f"Создан {CTL2_NAME} (XOR + перестановка байт)")

    # ctl3: метаданные, хранят инфу о скрытой папке и файлах (XOR + реверс)
    meta = json.dumps({
        'd':  DATA_DIR_NAME,
        'f1': CTL1_NAME,
        'f2': CTL2_NAME,
    })
    enc3 = scramble(meta.encode('utf-8'))
    with open(os.path.join(data_dir, CTL3_NAME), 'wb') as f:
        f.write(enc3)
    log(f"Создан {CTL3_NAME} (XOR + реверс для метаданных)")

    # создаём отвлекающие данные в реестре
    try:
        import winreg  # для работы с реестром windows
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                              r'Software\DoubleCipher') as key:
            winreg.SetValueEx(key, 'LicenseKey', 0, winreg.REG_SZ,
                              'DCSV-S7F9-28DM-EDS8')
            winreg.SetValueEx(key, 'ProductID', 0, winreg.REG_SZ,
                              'DEMO-3628')
            winreg.SetValueEx(key, 'InstallDate', 0, winreg.REG_SZ,
                              '2026-05-10')
        log("В реестр записаны отвлекающие данные")
    except Exception as e:
        log(f"Реестр пропущен: {e}")

    return install_root


# --------
# GUI
class InstallerApp:
    def __init__(self, root):
        self.root = root
        root.title("Установщик DoubleCipher")
        root.geometry("680x500")
        root.resizable(False, False)

        self.drives = []
        self.base_dir = get_base_dir()
        self.app_dir = os.path.join(self.base_dir, 'app')

        self._build_ui()
        self._refresh()

    def _build_ui(self):
        frame = ttk.Frame(self.root, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            frame,
            text="Выберите накопитель для привязки программы:",
            font=('Segoe UI', 10, 'bold'),
        ).pack(anchor=tk.W)

        list_frame = ttk.Frame(frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.listbox = tk.Listbox(list_frame, height=8,
                                  font=('Consolas', 10))
        scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL,
                               command=self.listbox.yview)
        self.listbox.config(yscrollcommand=scroll.set)
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=5)
        ttk.Button(btn_frame, text="Обновить список",
                   command=self._refresh).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="Установить",
                   command=self._install).pack(side=tk.LEFT, padx=5)

        ttk.Label(frame, text="Журнал:").pack(anchor=tk.W)
        self.log_text = tk.Text(frame, height=12,
                                font=('Consolas', 9), state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def _log(self, msg: str):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, msg + '\n')
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
        self.root.update_idletasks()

    def _refresh(self):
        self.listbox.delete(0, tk.END)
        self.drives = list_drives()
        for d in self.drives:
            line = (f"{d['root']}  {d['type']:<22}  "
                    f"SN: {d['serial']}  [{d['fs']}]")
            self.listbox.insert(tk.END, line)
        self._log(f"Найдено дисков: {len(self.drives)}")

    def _install(self):
        sel = self.listbox.curselection()
        if not sel:
            messagebox.showwarning("Внимание",
                                   "Выберите накопитель из списка.")
            return
        target = self.drives[sel[0]]

        if not messagebox.askyesno(
            "Подтверждение",
            f"Привязать программу к диску {target['root']}?\n\n"
            f"Тип: {target['type']}\n"
            f"Серийный номер: {target['serial']}\n\n"
            "После установки программа будет работать только "
            "при наличии этого накопителя."
        ):
            return

        try:
            install_root = do_install(target, self.app_dir, self._log)
            self._log("Установка завершена.")
            messagebox.showinfo(
                "Готово",
                f"Программа установлена в:\n{install_root}\n\n"
                "Запустите cipher_app.exe из этой папки."
            )
        except Exception as e:
            self._log(f"ОШИБКА: {e}")
            messagebox.showerror("Ошибка установки", str(e))


def main():
    root = tk.Tk()  # пустое окно
    InstallerApp(root)  # объект установщика в окне root
    root.mainloop()  # цикл обработки событий


if __name__ == '__main__':
    main()
