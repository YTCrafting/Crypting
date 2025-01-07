import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox

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

# function to encrypt a file
def encrypt_file(file_path, key):
    try:
        with open(file_path, 'rb') as f:
            original_data = f.read()
        backup_file_path = file_path + '.bup'
        with open(backup_file_path, 'wb') as f:
            f.write(original_data)
        encrypted_data = encryptData(original_data, key)
        for pattern_func, description in [
            (pattern_null, "Null byte pass over original file"),
            (pattern_random, "Random byte pass A over original file"),
            (pattern_ones, "All ones pass over original file"),
            (pattern_random, "Random byte pass B over original file"),
            (pattern_alternating, "Alternating bit pattern over original file"),
        ]:
            success, error = overwrite_file(file_path, pattern_func)
            if not success:
                return False
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)
        with open(file_path, 'rb') as f:
            new_encrypted_data = f.read()
        try:
            decrypted_data = decryptData(new_encrypted_data, key)
            if decrypted_data != original_data:
                return False
        except Exception as e:
            return False
        for pattern_func, description in [
            (pattern_null, "Null byte pass over backup file"),
            (pattern_random, "Random byte pass A over backup file"),
            (pattern_ones, "All ones pass over backup file"),
            (pattern_random, "Random byte pass B over backup file"),
            (pattern_alternating, "Alternating bit pattern over backup file"),
        ]:
            success, error = overwrite_file(backup_file_path, pattern_func)
            if not success:
                return False
        try:
            os.remove(backup_file_path)
        except Exception as e:
            return False
        new_file_path = file_path + '.enc'
        os.rename(file_path, new_file_path)
        return True
    except Exception as e:
        return False

# function to decrypt a file with a key
def decrypt_file(file_path, key):
    try:
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        try:
            decrypted_data = decryptData(encrypted_data, key)
        except Exception as e:
            return False
        backup_file_path = file_path + '.bup'
        with open(backup_file_path, 'wb') as f:
            f.write(encrypted_data)
        with open(file_path, 'wb') as f:
            f.write(decrypted_data)
        try:
            os.remove(backup_file_path)
        except Exception as e:
            return False
        if file_path.endswith('.enc'):
            original_file_path = file_path[:-4]
            os.rename(file_path, original_file_path)
        return True
    except Exception as e:
        return False

# init variables
files = []

# create window
root = tk.Tk()
root.title("Crypting")

# mode section
modeFrame = tk.Frame(root)
modeLabel = tk.Label(modeFrame, text="Mode:")
modeVariable = tk.StringVar(modeFrame, "Encrypt")
modeOptionMenu = tk.OptionMenu(modeFrame, modeVariable, "Encrypt", "Decrypt")
modeLabel.pack(side="left")
modeOptionMenu.pack(side="right")
modeFrame.pack(pady=5)

# files section
def filesUpdate():
    filesListbox.delete(0, tk.END)
    for item in files:
        filesListbox.insert(tk.END, item)

def filesAdd():
    file_path = filesText.get("1.0", tk.END).strip()
    if file_path:
        files.append(file_path)
        filesUpdate()

def filesRemoveSelected():
    selected = filesListbox.curselection()
    if selected:
        files.pop(selected[0])
        filesUpdate()

def filesChoose():
    file_path = filedialog.askopenfilename()
    if file_path:
        filesText.delete("1.0", tk.END)
        filesText.insert("1.0", file_path)

filesFrame = tk.Frame(root)
filesText = tk.Text(filesFrame, height=1, width=32)
filesButtonsFrame = tk.Frame(filesFrame)
filesButtonsAddButton = tk.Button(filesButtonsFrame, text="        Add        ", command=filesAdd)
filesButtonsRemoveButton = tk.Button(filesButtonsFrame, text="    Remove    ", command=filesRemoveSelected)
filesButtonsChooseButton = tk.Button(filesButtonsFrame, text="    Choose    ", command=filesChoose)
filesListbox = tk.Listbox(filesFrame, width=38)
filesButtonsAddButton.pack(side="left")
filesButtonsRemoveButton.pack(side="left")
filesButtonsChooseButton.pack(side="left")
filesText.pack()
filesButtonsFrame.pack(pady=5, padx=5)
filesListbox.pack(pady=5)
filesFrame.pack(pady=5)

# key section
keyFrame = tk.Frame(root)
keyLabel = tk.Label(keyFrame, text="Key:")
keyText = tk.Text(keyFrame, width=27, height=1)
keyLabel.pack(side="left", padx=5)
keyText.pack(side="right")
keyFrame.pack()

# start section
def startButtonCmd():
    key = keyText.get("1.0", tk.END).strip()
    mode = modeVariable.get()
    statuses = []
    for file in files:
        if mode == "Encrypt":
            status = encrypt_file(file, key)
        elif mode == "Decrypt":
            status = decrypt_file(file, key)
        statuses.append(status)
    if statuses.count(False) > 0:
        messagebox.showwarning(
            f"{statuses.count(False)} Errors",
            "\n".join(f"{'SUCCESS' if statuses[i] else 'FAILED'} - {file}" for i, file in enumerate(files))
        )
    else:
        messagebox.showinfo(
            "Success",
            "\n".join(f"{'SUCCESS' if statuses[i] else 'FAILED'} - {file}" for i, file in enumerate(files))
        )

startButton = tk.Button(root, text="              Start              ", command=startButtonCmd)
startButton.pack(pady=10)

# start app
root.mainloop()
