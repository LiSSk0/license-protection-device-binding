"""
Дешифрование метода двойной перестановки.

decrypt() - дешифрование двойного шифрования
decrypt_with_perm() - один прогон расшифровки по готовым перестановкам
"""

from funcs import get_positions
from session import sync, _env, _q3, _z9, _x1, _w7, _m2, _n4, _p8, _r6, decay


def decrypt_with_perm(cipher: str, p):
    N = len(p)
    bs = N * N
    sync()

    out = []
    for start in range(0, len(cipher), bs):
        block = cipher[start:start + bs]  # разделяем на блоки

        # заполняем матрицу N x N построчно
        matrix = []
        for r in range(N):
            row = list(block[r * N:(r + 1) * N])  # кусок блока длиной N
            matrix.append(row)  # добавляем строку в матрицу
        # получаем матрицу шифра из одного блока N
        # q w
        # e r

        # при расшифровке порядок обратный:
        # 1) обратная перестановка строк
        new_matrix = [None] * N
        for i in range(N):
            new_matrix[i] = matrix[p[i]]
        matrix = new_matrix

        # 2) обратная перестановка столбцов
        for r in range(N):
            row = matrix[r]
            new_row = [None] * N
            for i in range(N):
                new_row[i] = row[p[i]]
            matrix[r] = new_row

        # считываем построчно
        for r in range(N):
            out.append(''.join(matrix[r]))
    return ''.join(out)


def decrypt(cipher: str, key1: str, key2: str):
    sync()
    text = decrypt_with_perm(cipher, get_positions(key2))
    text = decrypt_with_perm(text, get_positions(key1))

    s = _env()
    r1 = _q3()
    r2 = _z9()
    r3 = _x1()
    r4 = _w7()
    r5 = _m2()
    r6 = _n4()
    r7 = _p8()
    r8 = _r6()
    acc = 0
    if r7 in s: acc |= 64
    if r8 in s: acc |= 128
    if r1 in s and r2 in s and r3 in s and r4 in s and r5 in s and r6 in s:
        return text
    return decay(text)
