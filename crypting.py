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

# create window
root = tk.Tk()
root.title("Crypting")

# mode dropdown
modeVar = tk.StringVar()
modeVar.set("Encrypt")
modeOptionMenu = tk.OptionMenu(root, modeVar, "Encrypt", "Decrypt")
modeOptionMenu.pack(pady = 20)

# selected file list
filelistFrame = tk.Frame(root)
filelistFrame.pack(padx = 10, pady = 10, fill = tk.BOTH, expand = True)
filelistScrollbar = tk.Scrollbar(filelistFrame)
filelistScrollbar.pack(side = tk.RIGHT, fill = tk.Y)
filelistListbox = tk.Listbox(filelistFrame, yscrollcommand = filelistScrollbar.set, height = 15, width = 40)
filelistListbox.pack(side = tk.LEFT, fill = tk.BOTH, expand = True)
filelistScrollbar.config(command = filelistListbox.yview)

# button to add file
def addfileCmd():
    filePath = filedialog.askopenfilename(title="Add File")
    if filePath:
        filelistListbox.insert(tk.END, filePath)
addfileButton = tk.Button(root, text = "Add File", command = addfileCmd)
addfileButton.pack(pady = 10)

# button to remove file
def removefileCmd():
    selected_indices = filelistListbox.curselection()
    for index in reversed(selected_indices):
        filelistListbox.delete(index)
removefileButton = tk.Button(root, text = "Remove File", command = removefileCmd)
removefileButton.pack(pady = 10)

# key input field
keyLabel = tk.Label(root, text = "Key")
keyLabel.pack(pady = (10, 0))
keyEntry = tk.Entry(root, width = 40)
keyEntry.pack(pady = (0, 10))

# start button
def startCmd():
    keyString = keyEntry.get()
    if not keyString:
        messagebox.showerror("Error", "Please enter a key.")
        return
    mode = modeVar.get()
    files = filelistListbox.get(0, tk.END)
    if not files:
        messagebox.showerror("Error", "Please add at least one file.")
        return
    for file in files:
        if not os.path.exists(file):
            messagebox.showerror("Error", f"File not found: {file}")
            continue
        if mode == "Encrypt":
            success = encrypt_file(file, keyString)
            if not success:
                messagebox.showinfo("Success", f"File encrypted: {file}")
            else:
                messagebox.showerror("Error", f"Failed to encrypt: {file}")
        elif mode == "Decrypt":
            success = decrypt_file(file, keyString)
            if success:
                messagebox.showinfo("Success", f"File decrypted: {file}")
            else:
                messagebox.showerror("Error", f"Failed to decrypt: {file}")
startButton = tk.Button(root, text = "Start", command = startCmd)
startButton.pack(pady = 10)

# start app
root.mainloop()
