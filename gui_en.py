import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

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
        return f"Error: {str(e)}"

# Fungsi saat tombol Enkripsi ditekan
def encrypt_text():
    text = entry_text.get("1.0", tk.END).strip()
    key = entry_key.get()
    if not text or not key:
        messagebox.showwarning("Peringatan", "Teks dan kunci harus diisi!")
        return
    encrypted = aes_encrypt(text, key)
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, encrypted)

# Fungsi saat tombol Dekripsi ditekan
def decrypt_text():
    encrypted = entry_text.get("1.0", tk.END).strip()
    key = entry_key.get()
    if not encrypted or not key:
        messagebox.showwarning("Peringatan", "Teks terenkripsi dan kunci harus diisi!")
        return
    decrypted = aes_decrypt(encrypted, key)
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, decrypted)

# GUI Setup
root = tk.Tk()
root.title("AES Enkripsi & Dekripsi")
root.geometry("500x500")

tk.Label(root, text="Masukkan Teks atau Enkripsi (Base64):").pack()
entry_text = tk.Text(root, height=5)
entry_text.pack(padx=10, pady=5, fill=tk.X)

tk.Label(root, text="Kunci (maks 32 karakter):").pack()
entry_key = tk.Entry(root, show="*", width=50)
entry_key.pack(padx=10, pady=5)

frame_btn = tk.Frame(root)
frame_btn.pack(pady=5)
tk.Button(frame_btn, text="🔐 Enkripsi", command=encrypt_text).pack(side=tk.LEFT, padx=10)
tk.Button(frame_btn, text="🔓 Dekripsi", command=decrypt_text).pack(side=tk.LEFT)

tk.Label(root, text="Output:").pack()
output_text = tk.Text(root, height=10)
output_text.pack(padx=10, pady=5, fill=tk.X)

root.mainloop()
