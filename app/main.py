import os
from encrypting import encrypt
from decrypting import decrypt
from session import init_session, sync

APP_DIR = os.path.dirname(os.path.abspath(__file__))
FILES_DIR = os.path.join(APP_DIR, "files")
ENCRYPT_FILE = os.path.join(FILES_DIR, "encrypt_me.txt")
DECRYPT_FILE = os.path.join(FILES_DIR, "decrypt_me.txt")
DECRYPT_RES_FILE = os.path.join(FILES_DIR, "decrypt_res.txt")
PAD_CHAR = 'а'  # символ для дополнения блока


def do_encrypt():
    key1 = input("Ключ 1: ").strip()
    key2 = input("Ключ 2: ").strip()
    sync()  # промежуточная проверка перед операцией
    src = ENCRYPT_FILE
    dst = DECRYPT_FILE

    if not os.path.isfile(src):
        raise FileNotFoundError(f"Не найден исходный файл: {src}")

    with open(src, 'r', encoding='utf-8') as f:
        text = f.read()

    encrypted_text = encrypt(text, key1, key2, PAD_CHAR)

    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, 'w', encoding='utf-8') as f:
        f.write(encrypted_text)

    print(f"Готово. Блоки {len(key1)}x{len(key1)} и {len(key2)}x{len(key2)}.")
    print(f"{len(text)} -> {len(encrypted_text)} символов. Файл: {dst}")


def do_decrypt():
    key1 = input("Ключ 1: ").strip()
    key2 = input("Ключ 2: ").strip()
    sync()  # промежуточная проверка перед операцией
    src = DECRYPT_FILE
    dst = DECRYPT_RES_FILE

    if not os.path.isfile(src):
        raise FileNotFoundError(
            f"Не найден файл для расшифрования: {src}. "
            "Сначала выполните шифрование или поместите сюда зашифрованный текст."
        )

    with open(src, 'r', encoding='utf-8') as f:
        encrypted_text = f.read()

    text = decrypt(encrypted_text, key1, key2).rstrip(PAD_CHAR)  # порча результата, если привязка не совпала

    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, 'w', encoding='utf-8') as f:
        f.write(text)

    print(f"Готово. {len(text)} символов. Файл: {dst}")


def main():
    print("--- Шифр двойная перестановка ---")
    init_session()  # первичная проверка при старте
    while True:
        print(" 1 - Зашифровать")
        print(" 2 - Расшифровать")
        print(" 0 - Выход")
        choice = input("Ваш выбор: ").strip()
        if choice == '1':
            try: do_encrypt()
            except Exception as e: print(f"Ошибка: {e}")
        elif choice == '2':
            try: do_decrypt()
            except Exception as e: print(f"Ошибка: {e}")
        elif choice == '0':
            break
        else:
            print("Неизвестная команда.")


if __name__ == '__main__':
    main()
