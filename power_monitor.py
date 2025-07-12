import wmi
import time
import os

def clear_screen():
    """Membersihkan layar konsol."""
    os.system('cls' if os.name == 'nt' else 'clear')

def get_power_data():
    """
    Mengambil data daya dari Open Hardware Monitor melalui WMI.
    Mengembalikan dictionary berisi nama sensor dan nilainya.
    """
    power_data = {}
    try:
        # Menghubungkan ke namespace WMI Open Hardware Monitor
        # Pastikan Open Hardware Monitor berjalan!
        c = wmi.WMI(namespace="root\\OpenHardwareMonitor")

        # Mengambil semua sensor dari OHM
        # Kita mencari sensor dengan SensorType 'Power'
        ohm_sensors = c.Sensor()

        for sensor in ohm_sensors:
            if sensor.SensorType == u'Power':
                # Contoh: 'CPU Package' - 30.5 W
                power_data[sensor.Name] = sensor.Value
    except wmi.WMIError as e:
        print(f"Error: Pastikan Open Hardware Monitor berjalan dengan WMI diaktifkan.")
        print(f"Detail Error: {e}")
        return None
    except Exception as e:
        print(f"Terjadi kesalahan tak terduga: {e}")
        return None
    return power_data

def display_power_data(data):
    """Menampilkan data daya yang diterima."""
    if data:
        print("--- Konsumsi Daya (Watt) ---")
        for name, value in data.items():
            # Format nilai ke dua desimal untuk tampilan yang lebih rapi
            print(f"{name}: {value:.2f} W")
        print("---------------------------")
    else:
        print("Tidak ada data daya yang tersedia.")

if __name__ == "__main__":
    print("Memulai pemantauan daya...")
    print("Pastikan Open Hardware Monitor berjalan di latar belakang.")
    print("Tekan Ctrl+C untuk berhenti.")

    try:
        while True:
            clear_screen()
            power_readings = get_power_data()
            display_power_data(power_readings)
            time.sleep(2) # Refresh setiap 2 detik
    except KeyboardInterrupt:
        print("\nPemantauan daya dihentikan.")
    except Exception as e:
        print(f"Program berhenti karena kesalahan: {e}")
