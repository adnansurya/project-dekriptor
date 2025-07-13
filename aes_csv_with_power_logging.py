# Full updated Python script with added CPU frequency and RAM usage (in GB) logging

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
    power_data = {}
    try:
        c = wmi.WMI(namespace="root\\OpenHardwareMonitor")
        for sensor in c.Sensor():
            if sensor.SensorType == u'Power':
                power_data[sensor.Name] = sensor.Value
    except:
        return None
    return power_data

def write_log_json(proses, file_asal, file_tujuan, status, durasi="", error="",
                   ukuran_asal="", ukuran_hasil="", avg_cpu=None, avg_ram=None,
                   avg_power=None, cpu_awal=None, ram_awal=None, power_awal=None,
                   cpu_freq_mhz=None, ram_used_gb=None, ram_total_gb=None):
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
    if avg_cpu is not None and avg_ram is not None:
        log_entry["rata_rata_cpu"] = f"{avg_cpu:.2f}%"
        log_entry["rata_rata_ram"] = f"{avg_ram:.2f}%"
    if avg_power is not None:
        log_entry["rata_rata_daya"] = f"{avg_power:.2f} W"
    if cpu_awal is not None:
        log_entry["cpu_awal"] = f"{cpu_awal:.1f}%"
    if ram_awal is not None:
        log_entry["ram_awal"] = f"{ram_awal:.1f}%"
    if power_awal is not None:
        log_entry["daya_awal"] = f"{power_awal:.2f} W"
    if cpu_freq_mhz is not None:
        log_entry["frekuensi_cpu"] = f"{cpu_freq_mhz:.0f} MHz"
    if ram_used_gb is not None and ram_total_gb is not None:
        log_entry["penggunaan_ram"] = f"{ram_used_gb:.2f} GB / {ram_total_gb:.2f} GB"

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

# AES helpers
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

def monitor_resources():
    global monitoring
    resource_info.clear()
    monitoring = True
    while monitoring:
        cpu = psutil.cpu_percent(interval=1)
        ram = psutil.virtual_memory().percent
        timestamp = datetime.now().strftime("%H:%M:%S")
        resource_info.append(f"[{timestamp}] CPU: {cpu}% | RAM: {ram}%")

def get_average_resource_usage():
    total_cpu = 0
    total_ram = 0
    count = len(resource_info)
    for line in resource_info:
        try:
            cpu_str = line.split("CPU:")[1].split("%")[0].strip()
            ram_str = line.split("RAM:")[1].split("%")[0].strip()
            total_cpu += float(cpu_str)
            total_ram += float(ram_str)
        except:
            continue
    avg_cpu = total_cpu / count if count else 0
    avg_ram = total_ram / count if count else 0
    return avg_cpu, avg_ram

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

    cpu_awal = psutil.cpu_percent(interval=0.5)
    ram_awal = psutil.virtual_memory().percent
    power_data_awal = get_power_data()
    power_awal = sum(power_data_awal.values()) / len(power_data_awal) if power_data_awal else None
    cpu_freq_mhz = psutil.cpu_freq().current if psutil.cpu_freq() else None
    virtual_mem = psutil.virtual_memory()
    ram_used_gb = virtual_mem.used / (1024**3)
    ram_total_gb = virtual_mem.total / (1024**3)

    write_log_json("ENKRIPSI", file_path, save_path, "MULAI", 0,
                   cpu_awal=cpu_awal, ram_awal=ram_awal, power_awal=power_awal,
                   cpu_freq_mhz=cpu_freq_mhz, ram_used_gb=ram_used_gb, ram_total_gb=ram_total_gb)

    monitor_thread = threading.Thread(target=monitor_resources)
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

        ukuran_asal = get_file_size(file_path)
        ukuran_hasil = get_file_size(save_path)
        avg_cpu, avg_ram = get_average_resource_usage()

        write_log_json("ENKRIPSI", file_path, save_path, "SUKSES", duration,
                       ukuran_asal=ukuran_asal, ukuran_hasil=ukuran_hasil,
                       avg_cpu=avg_cpu, avg_ram=avg_ram)

        messagebox.showinfo("Sukses", f"File berhasil dienkripsi.\n\nDurasi: {str(duration)}")
    except Exception as e:
        monitoring = False
        monitor_thread.join()
        write_log_json("ENKRIPSI", file_path, save_path, "GAGAL", error=str(e))
        messagebox.showerror("Error", f"Gagal mengenkripsi file:\n{e}")

# Same update logic applies to decrypt_csv() – can be appended similarly as encrypt_csv()

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

    cpu_awal = psutil.cpu_percent(interval=0.5)
    ram_awal = psutil.virtual_memory().percent
    power_data_awal = get_power_data()
    power_awal = sum(power_data_awal.values()) / len(power_data_awal) if power_data_awal else None
    cpu_freq_mhz = psutil.cpu_freq().current if psutil.cpu_freq() else None
    virtual_mem = psutil.virtual_memory()
    ram_used_gb = virtual_mem.used / (1024**3)
    ram_total_gb = virtual_mem.total / (1024**3)

    write_log_json("DEKRIPSI", file_path, save_path, "MULAI", 0,
                   cpu_awal=cpu_awal, ram_awal=ram_awal, power_awal=power_awal,
                   cpu_freq_mhz=cpu_freq_mhz, ram_used_gb=ram_used_gb, ram_total_gb=ram_total_gb)

    monitor_thread = threading.Thread(target=monitor_resources)
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

        ukuran_asal = get_file_size(file_path)
        ukuran_hasil = get_file_size(save_path)
        avg_cpu, avg_ram = get_average_resource_usage()

        write_log_json("DEKRIPSI", file_path, save_path, "SUKSES", duration,
                       ukuran_asal=ukuran_asal, ukuran_hasil=ukuran_hasil,
                       avg_cpu=avg_cpu, avg_ram=avg_ram)

        messagebox.showinfo("Sukses", f"File berhasil didekripsi.\n\nDurasi: {str(duration)}")
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
    log_window.geometry("700x500")

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
            for entry in logs:
                match_keyword = keyword in json.dumps(entry).lower()
                match_date = date_filter in entry["timestamp"] if date_filter else True
                if match_keyword and match_date:
                    text_widget.insert(tk.END, "-"*60 + "\n")
                    for k, v in entry.items():
                        label = k.replace("_", " ").title()
                        text_widget.insert(tk.END, f"{label}: {v}\n")
        except Exception as e:
            text_widget.insert(tk.END, f"Gagal membaca log: {e}")
        text_widget.config(state="disabled")

    def clear_logs():
        if messagebox.askyesno("Konfirmasi", "Yakin ingin menghapus semua riwayat?"):
            with open(LOG_JSON, "w", encoding="utf-8") as f:
                json.dump([], f)
            refresh_log_display()

    tk.Label(log_window, text="Cari:").pack(anchor="w", padx=10)
    tk.Entry(log_window, textvariable=search_var).pack(fill="x", padx=10)
    tk.Label(log_window, text="Filter Tanggal (YYYY-MM-DD):").pack(anchor="w", padx=10, pady=(5, 0))
    tk.Entry(log_window, textvariable=date_var).pack(fill="x", padx=10)

    btn_frame = tk.Frame(log_window)
    btn_frame.pack(pady=5)
    tk.Button(btn_frame, text="🔄 Refresh", command=refresh_log_display).pack(side="left", padx=5)
    tk.Button(btn_frame, text="🗑 Hapus Riwayat", command=clear_logs).pack(side="left", padx=5)

    text_widget = tk.Text(log_window, wrap="word")
    text_widget.pack(expand=True, fill="both", padx=10, pady=5)
    text_widget.config(state="disabled")

    refresh_log_display()
root = tk.Tk()
root.title("AES CSV Enkriptor/Dekriptor")
root.geometry("400x260")
root.resizable(False, False)

tk.Label(root, text="Masukkan Kunci AES:").pack(pady=10)
entry_key = tk.Entry(root, width=40, show="*")
entry_key.pack()

tk.Button(root, text="Enkripsi File CSV", command=encrypt_csv, width=30, bg="lightblue").pack(pady=10)
tk.Button(root, text="Dekripsi File CSV", command=decrypt_csv, width=30, bg="lightgreen").pack(pady=5)
tk.Button(root, text="Lihat Riwayat Proses", command=show_log_history, width=30, bg="lightyellow").pack(pady=5)

# Realtime CPU/RAM label
stat_label = tk.Label(root, text="CPU: - % | RAM: - %", fg="gray")
stat_label.pack(pady=5)

def update_stat_label():
    cpu = psutil.cpu_percent(interval=0.5)
    ram = psutil.virtual_memory().percent
    stat_label.config(text=f"CPU: {cpu:.1f}% | RAM: {ram:.1f}%")
    root.after(1000, update_stat_label)

update_stat_label()

root.mainloop()
