import tkinter as tk
from tkinter import filedialog, messagebox
import csv
import base64
import chardet
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# AES helper functions
def pad(s):
    pad_len = AES.block_size - len(s) % AES.block_size
    return s + bytes([pad_len]) * pad_len

def unpad(s):
    return s[:-s[-1]]

def get_key_and_iv(password):
    salt = b'static_salt'  # statik agar hasil dekripsi cocok
    key_iv = PBKDF2(password, salt, dkLen=32+16, count=100_000)
    return key_iv[:32], key_iv[32:]

def aes_encrypt(data, password):
    key, iv = get_key_and_iv(password)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(data.encode()))
    return base64.b64encode(ct_bytes).decode()

def aes_decrypt(data, password):
    key, iv = get_key_and_iv(password)
    try:
        ct = base64.b64decode(data)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct))
        return pt.decode()
    except Exception:
        return "[ERROR]"

# Deteksi encoding
def detect_encoding(file_path):
    with open(file_path, 'rb') as f:
        raw = f.read(10000)
        result = chardet.detect(raw)
        return result['encoding']

# Encrypt CSV File
def encrypt_csv():
    key = entry_key.get()
    if not key:
        messagebox.showwarning("Peringatan", "Masukkan kunci terlebih dahulu.")
        return

    file_path = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
    if not file_path:
        return

    save_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
    if not save_path:
        return

    try:
        encoding = detect_encoding(file_path)
        with open(file_path, newline='', encoding=encoding) as infile, \
             open(save_path, mode='w', newline='', encoding='utf-8') as outfile:
            reader = csv.reader(infile, delimiter='\t')
            writer = csv.writer(outfile, delimiter=';')
            header = next(reader)
            writer.writerow(header)
            for row in reader:
                encrypted_row = [aes_encrypt(cell, key) for cell in row]
                writer.writerow(encrypted_row)
        messagebox.showinfo("Sukses", "File berhasil dienkripsi dan disimpan.")
    except Exception as e:
        messagebox.showerror("Error", f"Gagal mengenkripsi file:\n{e}")

# Decrypt CSV File
def decrypt_csv():
    key = entry_key.get()
    if not key:
        messagebox.showwarning("Peringatan", "Masukkan kunci terlebih dahulu.")
        return

    file_path = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
    if not file_path:
        return

    save_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
    if not save_path:
        return

    try:
        encoding = detect_encoding(file_path)
        with open(file_path, newline='', encoding=encoding) as infile, \
             open(save_path, mode='w', newline='', encoding='utf-8') as outfile:
            reader = csv.reader(infile, delimiter=';')
            writer = csv.writer(outfile, delimiter='\t')
            header = next(reader)
            writer.writerow(header)
            for row in reader:
                decrypted_row = [aes_decrypt(cell, key) for cell in row]
                writer.writerow(decrypted_row)
        messagebox.showinfo("Sukses", "File berhasil didekripsi dan disimpan.")
    except Exception as e:
        messagebox.showerror("Error", f"Gagal mendekripsi file:\n{e}")

# GUI
root = tk.Tk()
root.title("AES CSV Enkriptor/Dekriptor")
root.geometry("400x200")
root.resizable(False, False)

tk.Label(root, text="Masukkan Kunci AES:").pack(pady=10)
entry_key = tk.Entry(root, width=40, show="*")
entry_key.pack()

tk.Button(root, text="Enkripsi File CSV", command=encrypt_csv, width=30, bg="lightblue").pack(pady=10)
tk.Button(root, text="Dekripsi File CSV", command=decrypt_csv, width=30, bg="lightgreen").pack(pady=5)

root.mainloop()
