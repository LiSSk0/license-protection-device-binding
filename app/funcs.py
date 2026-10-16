"""
Вспомогательные функции для:
encrypting.py
decrypting.py
"""

from math import gcd


# Дополняет текст до длины, кратной НОК размеров обоих блоков
def pad_text(text: str, N1: int, N2: int, pad_char: str):
    bs1 = N1 * N1
    bs2 = N2 * N2
    step = bs1 * bs2 // gcd(bs1, bs2)  # НОК, чтобы длина делилась на оба размера блока

    if len(text) % step:
        text += pad_char * (step - len(text) % step)
    return text


# узнаем позицию каждой буквы слова поочереди в алфавите (при совпадении букв они нумеруются слева направо)
# пример: СЛОН -> 3021
def get_positions(key: str):
    indexed = []
    for i in range(len(key)):
        indexed.append((key[i], i))
    indexed.sort()
    # СЛОН -> [(С,0), (Л,1), (О,2), (Н,3)] -> [(Л,1), (Н,3), (О,2), (С,0)]

    positions = [0] * len(key)
    for new_pos in range(len(indexed)):
        old_pos = indexed[new_pos][1]
        positions[old_pos] = new_pos
    # [(Л,1), (Н,3), (О,2), (С,0)] -> [3, 0, 2, 1]
    # С была 0 станет 3, Л была 1 станет 0, ...
    return positions
