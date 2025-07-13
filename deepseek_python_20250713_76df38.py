import tkinter as tk
from tkinter import filedialog, messagebox
import csv
import base64
import chardet
import os
import json
import threading
import time
import psutil
import wmi
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from datetime import datetime

LOG_JSON = "log.json"
LOG_FILE = "log.txt"
resource_info = []
monitoring = False

def get_file_size(path):
    try:
        size_bytes = os.path.getsize(path)
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024**2:
            return f"{size_bytes / 1024:.2f} KB"
        else:
            return f"{size_bytes / (1024**2):.2f} MB"
    except:
        return "-"

def get_power_data():
    try:
        c = wmi.WMI(namespace="root\\OpenHardwareMonitor")
        power_values = [sensor.Value for sensor in c.Sensor() if sensor.SensorType == 'Power']
        return sum(power_values)/len(power_values) if power_values else None
    except:
        return None

def write_log_json(proses, file_asal, file_tujuan, status, durasi="", error="",
                   ukuran_asal="", ukuran_hasil="", resource_data=None):
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "proses": proses,
        "file_asal": file_asal,
        "file_tujuan": file_tujuan,
        "status": status,
        "durasi": str(durasi),
        "error": error,
        "ukuran_asal": ukuran_asal,
        "ukuran_hasil": ukuran_hasil
    }
    
    if resource_data:
        if status == "MULAI":
            log_entry.update({
                "cpu_awal": f"{resource_data['cpu']:.1f}%",
                "cpu_freq_awal": f"{resource_data['cpu_freq']:.0f} MHz",
                "ram_awal": f"{resource_data['ram_percent']:.1f}%",
                "ram_used_awal": f"{resource_data['ram_used_gb']:.2f} GB",
                "power_awal": f"{resource_data['power']:.2f} W" if resource_data['power'] is not None else "-"
            })
        elif status == "SUKSES":
            log_entry.update({
                "cpu_avg": f"{resource_data['cpu_avg']:.1f}%",
                "cpu_freq_avg": f"{resource_data['cpu_freq_avg']:.0f} MHz",
                "ram_avg": f"{resource_data['ram_avg']:.1f}%",
                "ram_used_avg": f"{resource_data['ram_used_avg']:.2f} GB",
                "power_avg": f"{resource_data['power_avg']:.2f} W" if resource_data['power_avg'] is not None else "-"
            })

    logs = []
    if os.path.exists(LOG_JSON):
        with open(LOG_JSON, "r", encoding="utf-8") as f:
            try:
                logs = json.load(f)
            except:
                logs = []
    logs.append(log_entry)
    with open(LOG_JSON, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2, ensure_ascii=False)

def pad(s):
    pad_len = AES.block_size - len(s) % AES.block_size
    return s + bytes([pad_len]) * pad_len

def unpad(s):
    return s[:-s[-1]]

def get_key_and_iv(password):
    salt = b'static_salt'
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

def monitor_resources(resource_data):
    global monitoring
    monitoring = True
    cpu_samples = []
    ram_percent_samples = []
    ram_used_samples = []
    cpu_freq_samples = []
    power_samples = []

    while monitoring:
        cpu = psutil.cpu_percent(interval=1)
        ram = psutil.virtual_memory()
        cpu_freq = psutil.cpu_freq().current if psutil.cpu_freq() else None
        power = get_power_data()

        cpu_samples.append(cpu)
        ram_percent_samples.append(ram.percent)
        ram_used_samples.append(ram.used / (1024**3))
        if cpu_freq:
            cpu_freq_samples.append(cpu_freq)
        if power:
            power_samples.append(power)

    resource_data.update({
        'cpu_samples': cpu_samples,
        'ram_percent_samples': ram_percent_samples,
        'ram_used_samples': ram_used_samples,
        'cpu_freq_samples': cpu_freq_samples,
        'power_samples': power_samples
    })

def calculate_averages(resource_data):
    return {
        'cpu_avg': sum(resource_data['cpu_samples']) / len(resource_data['cpu_samples']) if resource_data['cpu_samples'] else 0,
        'ram_avg': sum(resource_data['ram_percent_samples']) / len(resource_data['ram_percent_samples']) if resource_data['ram_percent_samples'] else 0,
        'ram_used_avg': sum(resource_data['ram_used_samples']) / len(resource_data['ram_used_samples']) if resource_data['ram_used_samples'] else 0,
        'cpu_freq_avg': sum(resource_data['cpu_freq_samples']) / len(resource_data['cpu_freq_samples']) if resource_data['cpu_freq_samples'] else None,
        'power_avg': sum(resource_data['power_samples']) / len(resource_data['power_samples']) if resource_data['power_samples'] else None
    }

def detect_encoding(file_path):
    with open(file_path, 'rb') as f:
        raw = f.read(10000)
        result = chardet.detect(raw)
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

    # Capture initial resources
    resource_data = {
        'cpu': psutil.cpu_percent(interval=0.5),
        'ram_percent': psutil.virtual_memory().percent,
        'ram_used_gb': psutil.virtual_memory().used / (1024**3),
        'cpu_freq': psutil.cpu_freq().current if psutil.cpu_freq() else None,
        'power': get_power_data()
    }

    write_log_json("ENKRIPSI", file_path, save_path, "MULAI", 
                  resource_data=resource_data)

    # Start monitoring thread
    monitor_thread = threading.Thread(target=monitor_resources, args=(resource_data,))
    monitor_thread.start()

    try:
        start_time = datetime.now()
        encoding = detect_encoding(file_path)
        with open(file_path, newline='', encoding=encoding) as infile, \
             open(save_path, mode='w', newline='', encoding=encoding) as outfile:
            reader = csv.reader(infile, delimiter='\t')
            writer = csv.writer(outfile, delimiter=';')
            header = next(reader)
            writer.writerow(header)
            for row in reader:
                encrypted_row = [aes_encrypt(cell, key) for cell in row]
                writer.writerow(encrypted_row)
        
        end_time = datetime.now()
        duration = end_time - start_time

        global monitoring
        monitoring = False
        monitor_thread.join()

        # Calculate averages
        avg_data = calculate_averages(resource_data)
        
        write_log_json("ENKRIPSI", file_path, save_path, "SUKSES", duration,
                      ukuran_asal=get_file_size(file_path),
                      ukuran_hasil=get_file_size(save_path),
                      resource_data=avg_data)

        messagebox.showinfo("Sukses", f"File berhasil dienkripsi.\n\nDurasi: {duration}")
    except Exception as e:
        monitoring = False
        monitor_thread.join()
        write_log_json("ENKRIPSI", file_path, save_path, "GAGAL", error=str(e))
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

    # Capture initial resources
    resource_data = {
        'cpu': psutil.cpu_percent(interval=0.5),
        'ram_percent': psutil.virtual_memory().percent,
        'ram_used_gb': psutil.virtual_memory().used / (1024**3),
        'cpu_freq': psutil.cpu_freq().current if psutil.cpu_freq() else None,
        'power': get_power_data()
    }

    write_log_json("DEKRIPSI", file_path, save_path, "MULAI", 
                  resource_data=resource_data)

    # Start monitoring thread
    monitor_thread = threading.Thread(target=monitor_resources, args=(resource_data,))
    monitor_thread.start()

    try:
        start_time = datetime.now()
        encoding = detect_encoding(file_path)
        with open(file_path, newline='', encoding=encoding) as infile, \
             open(save_path, mode='w', newline='', encoding=encoding) as outfile:
            reader = csv.reader(infile, delimiter=';')
            writer = csv.writer(outfile, delimiter='\t')
            header = next(reader)
            writer.writerow(header)
            for row in reader:
                decrypted_row = [aes_decrypt(cell, key) for cell in row]
                writer.writerow(decrypted_row)
        
        end_time = datetime.now()
        duration = end_time - start_time

        global monitoring
        monitoring = False
        monitor_thread.join()

        # Calculate averages
        avg_data = calculate_averages(resource_data)
        
        write_log_json("DEKRIPSI", file_path, save_path, "SUKSES", duration,
                      ukuran_asal=get_file_size(file_path),
                      ukuran_hasil=get_file_size(save_path),
                      resource_data=avg_data)

        messagebox.showinfo("Sukses", f"File berhasil didekripsi.\n\nDurasi: {duration}")
    except Exception as e:
        monitoring = False
        monitor_thread.join()
        write_log_json("DEKRIPSI", file_path, save_path, "GAGAL", error=str(e))
        messagebox.showerror("Error", f"Gagal mendekripsi file:\n{e}")

def show_log_history():
    if not os.path.exists(LOG_JSON):
        messagebox.showinfo("Riwayat", "Belum ada riwayat proses.")
        return

    log_window = tk.Toplevel(root)
    log_window.title("Riwayat Proses")
    log_window.geometry("800x600")

    search_var = tk.StringVar()
    date_var = tk.StringVar()

    def refresh_log_display():
        text_widget.config(state="normal")
        text_widget.delete("1.0", tk.END)
        keyword = search_var.get().lower()
        date_filter = date_var.get().strip()
        
        try:
            with open(LOG_JSON, "r", encoding="utf-8") as f:
                logs = json.load(f)
            
            for entry in reversed(logs):  # Show newest first
                match_keyword = keyword in json.dumps(entry).lower()
                match_date = date_filter in entry["timestamp"] if date_filter else True
                
                if match_keyword and match_date:
                    text_widget.insert(tk.END, "="*80 + "\n")
                    for k, v in entry.items():
                        label = k.replace("_", " ").title()
                        text_widget.insert(tk.END, f"{label:20}: {v}\n")
                    text_widget.insert(tk.END, "\n")
        except Exception as e:
            text_widget.insert(tk.END, f"Gagal membaca log: {e}")
        text_widget.config(state="disabled")

    def clear_logs():
        if messagebox.askyesno("Konfirmasi", "Yakin ingin menghapus semua riwayat?"):
            with open(LOG_JSON, "w", encoding="utf-8") as f:
                json.dump([], f)
            refresh_log_display()

    # Search frame
    search_frame = tk.Frame(log_window)
    search_frame.pack(pady=10, padx=10, fill="x")
    
    tk.Label(log_window, text="Cari:").pack(anchor="w", padx=10)
    tk.Entry(log_window, textvariable=search_var).pack(fill="x", padx=10)
    tk.Label(log_window, text="Filter Tanggal (YYYY-MM-DD):").pack(anchor="w", padx=10, pady=(5, 0))
    tk.Entry(log_window, textvariable=date_var).pack(fill="x", padx=10)
    
    # Button frame
    btn_frame = tk.Frame(log_window)
    btn_frame.pack(pady=5)
    
    tk.Button(btn_frame, text="🔄 Refresh", command=refresh_log_display).pack(side="left", padx=5)
    tk.Button(btn_frame, text="🗑 Hapus Riwayat", command=clear_logs).pack(side="left", padx=5)
    tk.Button(btn_frame, text="📋 Copy", command=lambda: root.clipboard_append(text_widget.get("1.0", tk.END))).pack(side="left", padx=5)

    # Text widget
    text_frame = tk.Frame(log_window)
    text_frame.pack(expand=True, fill="both", padx=10, pady=5)
    
    text_widget = tk.Text(text_frame, wrap="word")
    scrollbar = tk.Scrollbar(text_frame, command=text_widget.yview)
    text_widget.configure(yscrollcommand=scrollbar.set)
    
    scrollbar.pack(side="right", fill="y")
    text_widget.pack(expand=True, fill="both")
    text_widget.config(state="disabled")

    refresh_log_display()

# Main GUI
root = tk.Tk()
root.title("AES CSV Enkriptor/Dekriptor")
root.geometry("400x300")
root.resizable(False, False)

# Key input
tk.Label(root, text="Masukkan Kunci AES:").pack(pady=10)
entry_key = tk.Entry(root, width=40, show="*")
entry_key.pack()

# Buttons
btn_frame = tk.Frame(root)
btn_frame.pack(pady=15)

tk.Button(btn_frame, text="Enkripsi File CSV", command=encrypt_csv, width=30, bg="lightblue").pack(pady=5)
tk.Button(btn_frame, text="Dekripsi File CSV", command=decrypt_csv, width=30, bg="lightgreen").pack(pady=5)
tk.Button(btn_frame, text="Lihat Riwayat Proses", command=show_log_history, width=30, bg="lightyellow").pack(pady=5)

# System monitor
monitor_frame = tk.Frame(root)
monitor_frame.pack(pady=10)

def update_stat_labels():
    cpu = psutil.cpu_percent(interval=0.5)
    ram = psutil.virtual_memory()
    cpu_freq = psutil.cpu_freq().current if psutil.cpu_freq() else None
    
    cpu_label.config(text=f"CPU: {cpu:.1f}%")
    ram_label.config(text=f"RAM: {ram.percent:.1f}% ({ram.used/(1024**3):.1f}/{ram.total/(1024**3):.1f} GB)")
    if cpu_freq:
        freq_label.config(text=f"Frekuensi: {cpu_freq:.0f} MHz")
    else:
        freq_label.config(text="Frekuensi: -")
    
    root.after(1000, update_stat_labels)

cpu_label = tk.Label(monitor_frame, text="CPU: -%", fg="blue")
cpu_label.pack(anchor="w")
ram_label = tk.Label(monitor_frame, text="RAM: -% (-/- GB)", fg="green")
ram_label.pack(anchor="w")
freq_label = tk.Label(monitor_frame, text="Frekuensi: - MHz", fg="purple")
freq_label.pack(anchor="w")

update_stat_labels()

root.mainloop()
