#!/usr/bin/env python3

import os
import sys
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"  # Silence TensorFlow messages
import pyinotify
import psutil
import subprocess
import threading
import time
import tensorflow as tf
from tensorflow.keras import layers, models
import numpy as np
from scapy.all import sniff, IP, TCP, UDP
import tkinter as tk
from tkinter import ttk, messagebox
import queue
import json
import logging
import sqlite3
from PyQt6 import QtWidgets, QtGui, QtCore

# Settings
VIDEO_DEVICES = ["/dev/video0", "/dev/video1"]
AUDIO_DEVICES = ["/dev/snd/pcm*"]
LOG_FILE = "/var/log/monitor_pro.log"
DB_FILE = "monitor_permissions.db"
SUSPICIOUS_PORTS = [1234, 4444, 8080]
NETWORK_INTERFACE = "wlan0"
HISTORY_SIZE = 50

# Queue for handling access requests
access_queue = queue.Queue()

# Setup JSON logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(message)s', filemode='a')
logger = logging.getLogger()

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS permissions
                 (process_path TEXT PRIMARY KEY, allowed INTEGER)''')  # 1 for always, 0 for no
    conn.commit()
    conn.close()

# Global variables
access_history = []
process_history = []

# Build LSTM model
def build_lstm_model():
    model = models.Sequential([
        layers.LSTM(32, input_shape=(HISTORY_SIZE, 4), return_sequences=True),
        layers.LSTM(16),
        layers.Dense(8, activation="relu"),
        layers.Dense(4, activation="linear")
    ])
    model.compile(optimizer="adam", loss="mse")
    return model

lstm_model = build_lstm_model()

# Helper functions
def get_process_info(device):
    try:
        result = subprocess.run(f"lsof {device}", shell=True, capture_output=True, text=True)
        lines = result.stdout.splitlines()
        if len(lines) > 1:
            pid = int(lines[1].split()[1])
            process = psutil.Process(pid)
            process_name = process.name()
            cmdline = " ".join(process.cmdline())
            if process_name in ["python", "python3"]:
                process_path = cmdline.split(" ")[1] if len(process.cmdline()) > 1 else cmdline
            else:
                process_path = process.exe()
            print(f"Detected access to {device} by {process_name} (PID: {pid}) at {process_path}")
            return process_name, pid, process.memory_percent(), process.cpu_percent(interval=0.1), process_path
    except Exception as e:
        print(f"Error detecting process for {device}: {e}")
    return None, None, 0, 0, None

def log_access(device, process_name, pid, allowed, anomaly_score, process_path):
    global process_history
    log_entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "device": device,
        "process_name": process_name,
        "pid": pid,
        "allowed": allowed,
        "anomaly_score": float(anomaly_score),
        "path": process_path
    }
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")
        logger.info(json.dumps(log_entry))
        process_history.append(log_entry)
        print(f"Logged access: {log_entry}")
    except Exception as e:
        print(f"Error writing log: {e}")

def block_process(pid):
    try:
        p = psutil.Process(pid)
        print(f"Terminating {p.name()} (PID: {pid}) - Command: {' '.join(p.cmdline())}")
        p.terminate()
    except Exception as e:
        print(f"Failed to terminate process {pid}: {e}")

def detect_anomaly(cpu_usage, mem_usage, pid):
    global access_history
    current_time = time.localtime()
    hour = current_time.tm_hour
    access_freq = sum(1 for x in access_history if x[2] == pid) / max(1, len(access_history))
    features = [cpu_usage, mem_usage, hour, access_freq]
    access_history.append([cpu_usage, mem_usage, pid, hour, access_freq])
    
    if len(access_history) < HISTORY_SIZE:
        return 0
    
    if len(access_history) > HISTORY_SIZE:
        access_history.pop(0)
    
    history_array = np.array([x[:2] + x[3:] for x in access_history]).reshape(1, HISTORY_SIZE, 4)
    reconstructed = lstm_model.predict(history_array, verbose=0)
    error = np.mean((history_array[0, -1] - reconstructed[0]) ** 2)
    lstm_model.fit(history_array, history_array, epochs=1, batch_size=1, verbose=0)
    return -error

def is_allowed_forever(process_path):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT allowed FROM permissions WHERE process_path=?", (process_path,))
    result = c.fetchone()
    conn.close()
    return result is not None and result[0] == 1

def save_permission(process_path, allowed):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO permissions VALUES (?, ?)", (process_path, 1 if allowed else 0))
    conn.commit()
    conn.close()

def show_access_popup(device, process_name, pid, cpu_usage, mem_usage, process_path):
    if is_allowed_forever(process_path):
        print(f"Permanent access granted for {process_name} (PID: {pid}) at {process_path}")
        return True
    
    root = tk.Tk()
    root.withdraw()
    
    anomaly_score = detect_anomaly(cpu_usage, mem_usage, pid)
    allowed = [None]

    def update_stats():
        if root.winfo_exists():
            try:
                p = psutil.Process(pid)
                cpu_label.config(text=f"CPU Usage: {p.cpu_percent(interval=0.1):.2f}%")
                mem_label.config(text=f"Memory Usage: {p.memory_percent():.2f}%")
                root.after(1000, update_stats)
            except:
                pass

    def on_allow():
        allowed[0] = True
        popup.destroy()

    def on_deny():
        allowed[0] = False
        popup.destroy()

    def on_always():
        allowed[0] = True
        save_permission(process_path, True)
        popup.destroy()

    popup = tk.Toplevel(root)
    popup.title(f"{process_name} Access Request")
    popup.geometry("400x350")
    popup.configure(bg="#f0f0f0")
    popup.attributes("-topmost", True)

    tk.Label(popup, text=f"Process: {process_name} (PID: {pid})", 
             bg="#f0f0f0", font=("Arial", 12, "bold")).pack(pady=10)
    tk.Label(popup, text=f"Device: {device}", 
             bg="#f0f0f0", font=("Arial", 10)).pack()
    cpu_label = tk.Label(popup, text=f"CPU Usage: {cpu_usage:.2f}%", 
                         bg="#f0f0f0", font=("Arial", 10))
    cpu_label.pack()
    mem_label = tk.Label(popup, text=f"Memory Usage: {mem_usage:.2f}%", 
                         bg="#f0f0f0", font=("Arial", 10))
    mem_label.pack()
    tk.Label(popup, text=f"Anomaly Score: {anomaly_score:.2f}", 
             bg="#f0f0f0", font=("Arial", 10)).pack(pady=5)
    tk.Label(popup, text=f"Path: {process_path}", 
             bg="#f0f0f0", font=("Arial", 10)).pack()
    tk.Label(popup, text="Allow access?", 
             bg="#f0f0f0", font=("Arial", 10)).pack(pady=5)

    btn_frame = tk.Frame(popup, bg="#f0f0f0")
    btn_frame.pack(pady=20)
    ttk.Button(btn_frame, text="Yes", command=on_allow).pack(side=tk.LEFT, padx=10)
    ttk.Button(btn_frame, text="No", command=on_deny).pack(side=tk.LEFT, padx=10)
    ttk.Button(btn_frame, text="Always", command=on_always).pack(side=tk.LEFT, padx=10)

    update_stats()
    print(f"Showing popup for {process_name} (PID: {pid}) at {process_path}")
    popup.wait_window()
    root.destroy()
    print(f"Popup response for {process_name} (PID: {pid}): {'Allowed' if allowed[0] else 'Denied'}")
    return allowed[0]

def process_access_requests():
    while True:
        device, process_name, pid, cpu_usage, mem_usage, process_path = access_queue.get()
        print(f"Processing access request: {process_name} (PID: {pid}) on {device} at {process_path}")
        allowed = show_access_popup(device, process_name, pid, cpu_usage, mem_usage, process_path)
        if not allowed:
            block_process(pid)
        log_access(device, process_name, pid, allowed, detect_anomaly(cpu_usage, mem_usage, pid), process_path)
        access_queue.task_done()

def analyze_network_traffic():
    def packet_callback(packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            suspicious = False
            if packet.haslayer(TCP) and packet[TCP].dport in SUSPICIOUS_PORTS:
                suspicious = True
            elif packet.haslayer(UDP) and packet[UDP].dport in SUSPICIOUS_PORTS:
                suspicious = True
            if suspicious:
                for pid in psutil.pids():
                    p = psutil.Process(pid)
                    try:
                        if any(device in [f.path for f in p.open_files()] for device in VIDEO_DEVICES + get_audio_devices()):
                            process_name, pid, cpu_usage, mem_usage, process_path = get_process_info(device)
                            if process_name:
                                access_queue.put((device, process_name, pid, cpu_usage, mem_usage, process_path))
                            break
                    except:
                        continue
    sniff(iface=NETWORK_INTERFACE, prn=packet_callback, store=0, filter="tcp or udp")

class DeviceWatcher(pyinotify.ProcessEvent):
    def process_IN_OPEN(self, event):
        device = event.pathname
        process_name, pid, mem_usage, cpu_usage, process_path = get_process_info(device)
        if process_name:
            access_queue.put((device, process_name, pid, cpu_usage, mem_usage, process_path))

def get_audio_devices():
    try:
        return [f"/dev/snd/{dev}" for dev in os.listdir("/dev/snd/") if dev.startswith("pcm")]
    except:
        return []

def show_process_list():
    root = tk.Tk()
    root.title("Process List")
    root.geometry("600x400")
    
    main_frame = ttk.Frame(root)
    main_frame.pack(fill="both", expand=True, padx=10, pady=10)
    
    listbox = tk.Listbox(main_frame, height=15, width=80, font=("Arial", 10))
    listbox.pack(side="left", fill="both", expand=True)
    
    scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=listbox.yview)
    scrollbar.pack(side="right", fill="y")
    listbox.config(yscrollcommand=scrollbar.set)
    
    for idx, entry in enumerate(process_history):
        status = "Allowed" if entry["allowed"] else "Denied"
        display_text = f"{entry['timestamp']} | {entry['process_name']} (PID: {entry['pid']}) | {status}"
        listbox.insert(tk.END, display_text)
    
    def delete_selected():
        try:
            selected_idx = listbox.curselection()[0]
            listbox.delete(selected_idx)
            process_history.pop(selected_idx)
            messagebox.showinfo("Deleted", "Item deleted successfully.")
        except IndexError:
            messagebox.showwarning("Error", "Please select an item.")
    
    ttk.Button(root, text="Delete Item", command=delete_selected).pack(pady=10)
    
    print("Showing process list")
    root.mainloop()

def show_log_list():
    root = tk.Tk()
    root.title("Log List")
    root.geometry("700x500")
    
    main_frame = ttk.Frame(root)
    main_frame.pack(fill="both", expand=True, padx=10, pady=10)
    
    search_frame = ttk.Frame(main_frame)
    search_frame.pack(fill="x", pady=5)
    ttk.Label(search_frame, text="Search: ").pack(side="left")
    search_var = tk.StringVar()
    search_entry = ttk.Entry(search_frame, textvariable=search_var)
    search_entry.pack(side="left", fill="x", expand=True, padx=5)
    
    listbox = tk.Listbox(main_frame, height=20, width=90, font=("Arial", 10))
    listbox.pack(side="left", fill="both", expand=True)
    
    scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=listbox.yview)
    scrollbar.pack(side="right", fill="y")
    listbox.config(yscrollcommand=scrollbar.set)
    
    def load_logs(search_text=""):
        listbox.delete(0, tk.END)
        try:
            if not os.path.exists(LOG_FILE):
                listbox.insert(tk.END, "Log file not found.")
                print("Log file not found")
                return
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                lines = f.readlines()
                if not lines:
                    listbox.insert(tk.END, "Log file is empty.")
                    print("Log file is empty")
                    return
                for line in lines:
                    if not line.strip():
                        continue
                    if search_text.lower() in line.lower():
                        try:
                            log_entry = json.loads(line.strip())
                            display_text = f"{log_entry['timestamp']} | {log_entry['process_name']} (PID: {log_entry['pid']}) | {log_entry['device']} | {'Allowed' if log_entry['allowed'] else 'Denied'}"
                            listbox.insert(tk.END, display_text)
                        except json.JSONDecodeError as e:
                            print(f"Failed to parse log line: {line.strip()} - Error: {e}")
                            listbox.insert(tk.END, f"Invalid log entry: {line.strip()}")
        except Exception as e:
            print(f"Error reading log file: {e}")
            listbox.insert(tk.END, f"Error reading log file: {e}")
    
    def on_search(*args):
        load_logs(search_var.get())
    
    search_var.trace("w", on_search)
    load_logs()
    
    print("Showing log list")
    root.mainloop()

def setup_system_tray():
    app = QtWidgets.QApplication(sys.argv)
    tray_icon = QtWidgets.QSystemTrayIcon()
    icon = QtGui.QIcon("icon.png")
    tray_icon.setIcon(icon)
    tray_icon.setToolTip("Process Monitor")

    # Create context menu with PyQt6
    menu = QtWidgets.QMenu()
    
    process_action = menu.addAction("Show Processes")
    process_action.triggered.connect(lambda: threading.Thread(target=show_process_list, daemon=True).start())
    
    log_action = menu.addAction("Show Logs")
    log_action.triggered.connect(lambda: threading.Thread(target=show_log_list, daemon=True).start())
    
    tray_icon.setContextMenu(menu)
    tray_icon.show()
    
    # Start monitoring in a separate thread
    monitor_thread = threading.Thread(target=start_monitoring, daemon=True)
    monitor_thread.start()
    
    app.exec()

def start_monitoring():
    try:
        open(LOG_FILE, "a").close()  # Ensure log file exists
    except Exception as e:
        print(f"Failed to create log file: {e}")

    init_db()
    wm = pyinotify.WatchManager()
    handler = DeviceWatcher()
    notifier = pyinotify.ThreadedNotifier(wm, handler)
    notifier.start()

    for device in VIDEO_DEVICES + get_audio_devices():
        if os.path.exists(device):
            wm.add_watch(device, pyinotify.IN_OPEN)
            print(f"Monitoring {device}")

    network_thread = threading.Thread(target=analyze_network_traffic, daemon=True)
    network_thread.start()

    queue_thread = threading.Thread(target=process_access_requests, daemon=True)
    queue_thread.start()

    print("Monitoring started in background. Running silently...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping monitor...")
        notifier.stop()

def main():
    setup_system_tray()

if __name__ == "__main__":
    main()
