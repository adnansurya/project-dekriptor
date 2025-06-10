import tkinter as tk
from tkinter import filedialog, messagebox
import csv
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import chardet



# Fungsi AES Encrypt
def aes_encrypt(plain_text, key):
    key = key.ljust(32)[:32].encode()
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
    encrypted_data = base64.b64encode(iv + encrypted).decode()
    return encrypted_data

# Fungsi AES Decrypt
def aes_decrypt(encrypted_data, key):
    try:
        key = key.ljust(32)[:32].encode()
        encrypted_data = base64.b64decode(encrypted_data.encode())
        iv = encrypted_data[:16]
        encrypted_text = encrypted_data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted_text), AES.block_size).decode()
        return decrypted
    except Exception as e:
        return f"ERROR: {str(e)}"

# GUI Functions
def encrypt_text():
    text = entry_text.get("1.0", tk.END).strip()
    key = entry_key.get()
    if not text or not key:
        messagebox.showwarning("Peringatan", "Isi teks dan kunci terlebih dahulu!")
        return
    encrypted = aes_encrypt(text, key)
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, encrypted)

def decrypt_text():
    encrypted = entry_text.get("1.0", tk.END).strip()
    key = entry_key.get()
    if not encrypted or not key:
        messagebox.showwarning("Peringatan", "Isi teks terenkripsi dan kunci terlebih dahulu!")
        return
    decrypted = aes_decrypt(encrypted, key)
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, decrypted)

def detect_encoding(file_path):
    with open(file_path, 'rb') as f:
        raw_data = f.read(10000)  # baca sebagian file
        result = chardet.detect(raw_data)
        return result['encoding']

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
        with open(file_path, newline='', encoding=encoding) as infile, open(save_path, mode='w', newline='', encoding='utf-8') as outfile:
            reader = csv.reader(infile, delimiter='\t')
            writer = csv.writer(outfile, delimiter='\t')
            header = next(reader)
            writer.writerow(header)
            for row in reader:
                encrypted_row = [aes_encrypt(cell, key) for cell in row]
                writer.writerow(encrypted_row)
        messagebox.showinfo("Sukses", "File berhasil dienkripsi dan disimpan.")
    except Exception as e:
        messagebox.showerror("Error", f"Gagal mengenkripsi file:\n{e}")

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
        with open(file_path, newline='', encoding=encoding) as infile, open(save_path, mode='w', newline='', encoding='utf-8') as outfile:
            reader = csv.reader(infile, delimiter='\t')
            writer = csv.writer(outfile, delimiter='\t')
            header = next(reader)
            writer.writerow(header)
            for row in reader:
                decrypted_row = [aes_decrypt(cell, key) for cell in row]
                writer.writerow(decrypted_row)
        messagebox.showinfo("Sukses", "File berhasil didekripsi dan disimpan.")
    except Exception as e:
        messagebox.showerror("Error", f"Gagal mendekripsi file:\n{e}")


# GUI Setup
root = tk.Tk()
root.title("AES Enkripsi & Dekripsi dengan CSV")
root.geometry("550x600")

tk.Label(root, text="Teks Input / Enkripsi (Base64):").pack()
entry_text = tk.Text(root, height=5)
entry_text.pack(padx=10, pady=5, fill=tk.X)

tk.Label(root, text="Kunci (maks 32 karakter):").pack()
entry_key = tk.Entry(root, show="*", width=50)
entry_key.pack(padx=10, pady=5)

frame_btn = tk.Frame(root)
frame_btn.pack(pady=5)
tk.Button(frame_btn, text="🔐 Enkripsi", command=encrypt_text).pack(side=tk.LEFT, padx=10)
tk.Button(frame_btn, text="🔓 Dekripsi", command=decrypt_text).pack(side=tk.LEFT)

frame_csv = tk.LabelFrame(root, text="CSV Operations", padx=10, pady=10)
frame_csv.pack(pady=15, fill="x", padx=10)
tk.Button(frame_csv, text="📂 Enkripsi File CSV", command=encrypt_csv, width=25).pack(pady=5)
tk.Button(frame_csv, text="📂 Dekripsi File CSV", command=decrypt_csv, width=25).pack(pady=5)

tk.Label(root, text="Output:").pack()
output_text = tk.Text(root, height=10)
output_text.pack(padx=10, pady=5, fill=tk.X)

root.mainloop()
