import os
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import msvcrt
import colorama

# initialize colorama
colorama.init()

# raw encryption function
def encryptData(data: bytes, key: str) -> bytes:
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    derived_key = kdf.derive(key.encode('utf-8'))
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    tag = encryptor.tag
    return salt + nonce + tag + ciphertext

# raw decryption function
def decryptData(encData: bytes, key: str) -> bytes:
    salt = encData[:16]
    nonce = encData[16:28]
    tag = encData[28:44]
    ciphertext = encData[44:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    derived_key = kdf.derive(key.encode('utf-8'))
    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    data = decryptor.update(ciphertext) + decryptor.finalize()
    return data

# overwriting patterns
def pattern_null(size):
    return b'\x00' * size
def pattern_random(size):
    return os.urandom(size)
def pattern_ones(size):
    return b'\xFF' * size
def pattern_alternating(size):
    return b'\xAA' * size

# function to overwrite file
def overwrite_file(file_path, pattern_func):
    try:
        file_size = os.path.getsize(file_path)
        with open(file_path, 'wb') as f:
            chunk_size = 64 * 1024
            total_written = 0
            while total_written < file_size:
                write_size = min(chunk_size, file_size - total_written)
                pattern = pattern_func(write_size)
                f.write(pattern)
                total_written += write_size
        return True, None
    except Exception as e:
        return False, str(e)

# masked input for keys
def masked_input(prompt="", mask_char="*"):
    sys.stdout.write(prompt)
    sys.stdout.flush()
    password = ""
    while True:
        char = msvcrt.getch()
        if char == b'\r':
            break
        elif char == b'\b':
            if len(password) > 0:
                sys.stdout.write('\b \b')
                sys.stdout.flush()
                password = password[:-1]
        elif char != b'\x00' and char != b'\xe0':
            sys.stdout.write(mask_char)
            sys.stdout.flush()
            password += char.decode('utf-8')
    sys.stdout.write('\n')
    return password

# print extensions
def print_status(step_number, total_steps, message):
    print(f"{colorama.Fore.BLUE}[{step_number}/{total_steps}] {message}... ", end='', flush=True)
def print_done():
    print(f"{colorama.Fore.GREEN}Done!{colorama.Fore.RESET}")

# gets mode from user
def get_mode():
    while True:
        mode = input(f"{colorama.Fore.YELLOW}Mode > {colorama.Fore.RESET}").strip().lower()
        if mode == 'e' or mode == 'd':
            return mode
        else:
            print(f"{colorama.Fore.RED}Error: Invalid Mode!{colorama.Fore.RESET}")
            print(f"{colorama.Fore.YELLOW}E = Encrypt{colorama.Fore.RESET}")
            print(f"{colorama.Fore.YELLOW}D = Decrypt{colorama.Fore.RESET}")

# gets file path from user
def get_file_path():
    while True:
        file_path = input(f"{colorama.Fore.YELLOW}File Path > {colorama.Fore.RESET}").strip()
        if os.path.isfile(file_path):
            return file_path
        else:
            print(f"{colorama.Fore.RED}Error: Invalid File!{colorama.Fore.RESET}")

# gets key from user
def get_key(verify=False):
    key = masked_input(f"{colorama.Fore.YELLOW}Key > {colorama.Fore.RESET}")
    if verify:
        confirm_key = masked_input(f"{colorama.Fore.YELLOW}Verify Key > {colorama.Fore.RESET}")
        if key != confirm_key:
            print(f"{colorama.Fore.RED}Error: Keys do not match! Please try again.{colorama.Fore.RESET}")
            return get_key(verify=True)
    return key

# yes no prompt
def yes_no_prompt(prompt):
    while True:
        choice = input(f"{colorama.Fore.YELLOW}{prompt} > {colorama.Fore.RESET}").strip().lower()
        if choice == 'y':
            return True
        elif choice == 'n':
            return False
        else:
            print(f"{colorama.Fore.RED}Error: Invalid input for yes/no question!{colorama.Fore.RESET}")
            print(f"{colorama.Fore.YELLOW}Y = Yes{colorama.Fore.RESET}")
            print(f"{colorama.Fore.YELLOW}N = No{colorama.Fore.RESET}")

# function to encrypt a file
def encrypt_file(file_path, key):
    total_steps = 17
    step = 1
    try:
        print_status(step, total_steps, "Reading file")
        with open(file_path, 'rb') as f:
            original_data = f.read()
        print_done()
        step += 1

        print_status(step, total_steps, "Creating temporary backup")
        backup_file_path = file_path + '.bup'
        with open(backup_file_path, 'wb') as f:
            f.write(original_data)
        print_done()
        step += 1

        print_status(step, total_steps, "Preparing encryption algorithm")
        print_done()
        step += 1

        print_status(step, total_steps, "Encrypting file data")
        encrypted_data = encryptData(original_data, key)
        print_done()
        step += 1

        for pattern_func, description in [
            (pattern_null, "Null byte pass over original file"),
            (pattern_random, "Random byte pass A over original file"),
            (pattern_ones, "All ones pass over original file"),
            (pattern_random, "Random byte pass B over original file"),
            (pattern_alternating, "Alternating bit pattern over original file"),
        ]:
            print_status(step, total_steps, description)
            success, error = overwrite_file(file_path, pattern_func)
            if not success:
                print(f"{colorama.Fore.RED}Failed! Error: {error}{colorama.Fore.RESET}")
                return False
            print_done()
            step += 1

        print_status(step, total_steps, "Writing encrypted data to original file")
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)
        print_done()
        step += 1

        print_status(step, total_steps, "Verifying encrypted data")
        with open(file_path, 'rb') as f:
            new_encrypted_data = f.read()
        try:
            decrypted_data = decryptData(new_encrypted_data, key)
            if decrypted_data != original_data:
                print(f"{colorama.Fore.RED}Failed! Verification failed.{colorama.Fore.RESET}")
                return False
        except Exception as e:
            print(f"{colorama.Fore.RED}Failed! Error: {e}{colorama.Fore.RESET}")
            return False
        print_done()
        step += 1

        for pattern_func, description in [
            (pattern_null, "Null byte pass over backup file"),
            (pattern_random, "Random byte pass A over backup file"),
            (pattern_ones, "All ones pass over backup file"),
            (pattern_random, "Random byte pass B over backup file"),
            (pattern_alternating, "Alternating bit pattern over backup file"),
        ]:
            print_status(step, total_steps, description)
            success, error = overwrite_file(backup_file_path, pattern_func)
            if not success:
                print(f"{colorama.Fore.RED}Failed! Error: {error}{colorama.Fore.RESET}")
                return False
            print_done()
            step += 1

        print_status(step, total_steps, "Deleting backup file")
        try:
            os.remove(backup_file_path)
        except Exception as e:
            print(f"{colorama.Fore.RED}Failed! Error: {e}{colorama.Fore.RESET}")
            return False
        print_done()

        new_file_path = file_path + '.enc'
        os.rename(file_path, new_file_path)

        print(f"{colorama.Fore.GREEN}Encryption of file successful!{colorama.Fore.RESET}")
        return True

    except Exception as e:
        print(f"{colorama.Fore.RED}Failed! Error: {e}{colorama.Fore.RESET}")
        return False

# function to decrypt a file with a key
def decrypt_file(file_path, key):
    total_steps = 5
    step = 1
    try:
        if not file_path.endswith('.enc'):
            print(f"{colorama.Fore.YELLOW}Warning: File does not end in .enc extension!{colorama.Fore.RESET}")
            proceed = yes_no_prompt("Proceed?")
            if not proceed:
                print(f"{colorama.Fore.RED}Decryption of file aborted.{colorama.Fore.RESET}")
                return False

        print_status(step, total_steps, "Reading file")
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        print_done()
        step += 1

        print_status(step, total_steps, "Decrypting file data")
        try:
            decrypted_data = decryptData(encrypted_data, key)
            print_done()
            step += 1
        except Exception as e:
            print(f"{colorama.Fore.RED}Failed! Error: {e}{colorama.Fore.RESET}")
            return False

        print_status(step, total_steps, "Creating temporary backup")
        backup_file_path = file_path + '.bup'
        with open(backup_file_path, 'wb') as f:
            f.write(encrypted_data)
        print_done()
        step += 1

        print_status(step, total_steps, "Writing data to original file")
        with open(file_path, 'wb') as f:
            f.write(decrypted_data)
        print_done()
        step += 1

        print_status(step, total_steps, "Deleting backup")
        try:
            os.remove(backup_file_path)
        except Exception as e:
            print(f"{colorama.Fore.RED}Failed! Error: {e}{colorama.ore.RESET}")
            return False
        print_done()

        if file_path.endswith('.enc'):
            original_file_path = file_path[:-4]
            os.rename(file_path, original_file_path)

        print(f"{colorama.Fore.GREEN}Decryption of file successful!{colorama.Fore.RESET}")
        return True

    except Exception as e:
        print(f"{colorama.Fore.RED}Failed! Error: {e}{colorama.Fore.RESET}")
        return False

# main function
def main():
    while True:
        mode = get_mode()
        file_path = get_file_path()
        key = get_key(verify=(mode == 'e'))

        if mode == 'e':
            success = encrypt_file(file_path, key)
        elif mode == 'd':
            success = decrypt_file(file_path, key)

        continue_program = yes_no_prompt("Continue?")
        if not continue_program:
            print(f"{colorama.Fore.GREEN}Exiting program. Goodbye!{colorama.Fore.RESET}")
            break

if __name__ == '__main__':
    main()
