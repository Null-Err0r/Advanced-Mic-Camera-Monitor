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
import json
import logging
import sqlite3
from PyQt6 import QtWidgets, QtGui, QtCore

# Settings
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VIDEO_DEVICES = ["/dev/video0", "/dev/video1"]
LOG_FILE = "/var/log/monitor_pro.log" if os.geteuid() == 0 else os.path.join(BASE_DIR, "monitor_pro.log")
DB_FILE = os.path.join(BASE_DIR, "monitor_permissions.db")
MODEL_FILE = os.path.join(BASE_DIR, "monitor_model.keras")
SUSPICIOUS_PORTS = [1234, 4444, 8080]
HISTORY_SIZE = 50

# Setup JSON logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(message)s', filemode='a')
logger = logging.getLogger()

# Global variables
access_history = []
process_history = []

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS permissions
                 (process_path TEXT PRIMARY KEY, allowed INTEGER)''')  # 1 for always, 0 for no
    conn.commit()
    conn.close()

def build_lstm_model():
    model = models.Sequential([
        layers.LSTM(32, input_shape=(HISTORY_SIZE, 4), return_sequences=True),
        layers.LSTM(16),
        layers.Dense(8, activation="relu"),
        layers.Dense(4, activation="linear")
    ])
    model.compile(optimizer="adam", loss="mse")
    return model

# Load or build model
if os.path.exists(MODEL_FILE):
    try:
        lstm_model = tf.keras.models.load_model(MODEL_FILE)
        print("Loaded existing LSTM model.")
    except Exception as e:
        print(f"Failed to load model: {e}. Building new one.")
        lstm_model = build_lstm_model()
else:
    lstm_model = build_lstm_model()

# Helper functions
def get_process_info(device):
    try:
        result = subprocess.run(f"lsof -t {device}", shell=True, capture_output=True, text=True)
        pids = result.stdout.strip().split('\n')
        if pids and pids[0]:
            pid = int(pids[0])
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
        # Avoid noisy output when lsof fails
        pass
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
    access_history.append([cpu_usage, mem_usage, pid, hour, access_freq])
    
    if len(access_history) < HISTORY_SIZE:
        return 0
    
    if len(access_history) > HISTORY_SIZE:
        access_history.pop(0)
    
    history_array = np.array([x[:2] + x[3:] for x in access_history]).reshape(1, HISTORY_SIZE, 4)
    reconstructed = lstm_model.predict(history_array, verbose=0)
    error = np.mean((history_array[0, -1] - reconstructed[0]) ** 2)
    lstm_model.fit(history_array, history_array, epochs=1, batch_size=1, verbose=0)
    
    # Save model periodically
    try:
        lstm_model.save(MODEL_FILE)
    except Exception as e:
        print(f"Error saving model: {e}")
        
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

# PyQt Signals for Thread-to-GUI communication
class MonitorSignals(QtCore.QObject):
    request_access = QtCore.pyqtSignal(str, str, int, float, float, str)
    
monitor_signals = MonitorSignals()

class AccessPopup(QtWidgets.QDialog):
    def __init__(self, device, process_name, pid, cpu_usage, mem_usage, process_path, anomaly_score):
        super().__init__()
        self.setWindowTitle(f"{process_name} Access Request")
        self.setFixedSize(400, 300)
        self.setWindowFlags(self.windowFlags() | QtCore.Qt.WindowType.WindowStaysOnTopHint)
        self.allowed = False
        self.pid = pid
        self.process_path = process_path
        
        layout = QtWidgets.QVBoxLayout()
        
        lbl_proc = QtWidgets.QLabel(f"<b>Process:</b> {process_name} (PID: {pid})")
        lbl_dev = QtWidgets.QLabel(f"<b>Device:</b> {device}")
        
        self.lbl_cpu = QtWidgets.QLabel(f"<b>CPU Usage:</b> {cpu_usage:.2f}%")
        self.lbl_mem = QtWidgets.QLabel(f"<b>Memory Usage:</b> {mem_usage:.2f}%")
        lbl_anomaly = QtWidgets.QLabel(f"<b>Anomaly Score:</b> {anomaly_score:.2f}")
        lbl_path = QtWidgets.QLabel(f"<b>Path:</b> {process_path}")
        lbl_path.setWordWrap(True)
        
        layout.addWidget(lbl_proc)
        layout.addWidget(lbl_dev)
        layout.addWidget(self.lbl_cpu)
        layout.addWidget(self.lbl_mem)
        layout.addWidget(lbl_anomaly)
        layout.addWidget(lbl_path)
        
        lbl_q = QtWidgets.QLabel("Allow access?")
        layout.addWidget(lbl_q)
        
        btn_layout = QtWidgets.QHBoxLayout()
        btn_yes = QtWidgets.QPushButton("Yes")
        btn_no = QtWidgets.QPushButton("No")
        btn_always = QtWidgets.QPushButton("Always")
        
        btn_yes.clicked.connect(self.on_allow)
        btn_no.clicked.connect(self.on_deny)
        btn_always.clicked.connect(self.on_always)
        
        btn_layout.addWidget(btn_yes)
        btn_layout.addWidget(btn_no)
        btn_layout.addWidget(btn_always)
        
        layout.addLayout(btn_layout)
        self.setLayout(layout)
        
        # Timer to update CPU/Mem
        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.update_stats)
        self.timer.start(1000)

    def update_stats(self):
        try:
            p = psutil.Process(self.pid)
            self.lbl_cpu.setText(f"<b>CPU Usage:</b> {p.cpu_percent(interval=0.1):.2f}%")
            self.lbl_mem.setText(f"<b>Memory Usage:</b> {p.memory_percent():.2f}%")
        except:
            self.timer.stop()
            
    def on_allow(self):
        self.allowed = True
        self.accept()
        
    def on_deny(self):
        self.allowed = False
        self.reject()
        
    def on_always(self):
        self.allowed = True
        save_permission(self.process_path, True)
        self.accept()

class LogViewer(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Log List")
        self.resize(700, 500)
        
        layout = QtWidgets.QVBoxLayout()
        search_layout = QtWidgets.QHBoxLayout()
        search_layout.addWidget(QtWidgets.QLabel("Search:"))
        self.search_entry = QtWidgets.QLineEdit()
        self.search_entry.textChanged.connect(self.load_logs)
        search_layout.addWidget(self.search_entry)
        
        layout.addLayout(search_layout)
        
        self.list_widget = QtWidgets.QListWidget()
        layout.addWidget(self.list_widget)
        self.setLayout(layout)
        
        self.load_logs()
        
    def load_logs(self, search_text=""):
        self.list_widget.clear()
        try:
            if not os.path.exists(LOG_FILE):
                self.list_widget.addItem("Log file not found.")
                return
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                lines = f.readlines()
                if not lines:
                    self.list_widget.addItem("Log file is empty.")
                    return
                for line in lines:
                    if not line.strip(): continue
                    if search_text.lower() in line.lower():
                        try:
                            entry = json.loads(line.strip())
                            status = "Allowed" if entry['allowed'] else "Denied"
                            display_text = f"{entry['timestamp']} | {entry['process_name']} (PID: {entry['pid']}) | {entry['device']} | {status}"
                            self.list_widget.addItem(display_text)
                        except:
                            self.list_widget.addItem(f"Invalid log entry: {line.strip()}")
        except Exception as e:
            self.list_widget.addItem(f"Error reading log file: {e}")

class ProcessViewer(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Process List")
        self.resize(600, 400)
        
        layout = QtWidgets.QVBoxLayout()
        self.list_widget = QtWidgets.QListWidget()
        
        for entry in process_history:
            status = "Allowed" if entry["allowed"] else "Denied"
            display_text = f"{entry['timestamp']} | {entry['process_name']} (PID: {entry['pid']}) | {status}"
            
            item = QtWidgets.QListWidgetItem(display_text)
            item.setData(QtCore.Qt.ItemDataRole.UserRole, entry)
            self.list_widget.addItem(item)
            
        layout.addWidget(self.list_widget)
        
        btn_del = QtWidgets.QPushButton("Delete Item")
        btn_del.clicked.connect(self.delete_selected)
        layout.addWidget(btn_del)
        
        self.setLayout(layout)
        
    def delete_selected(self):
        selected = self.list_widget.currentRow()
        if selected >= 0:
            self.list_widget.takeItem(selected)
            if selected < len(process_history):
                process_history.pop(selected)
            QtWidgets.QMessageBox.information(self, "Deleted", "Item deleted successfully.")

class TrayApp(QtWidgets.QApplication):
    def __init__(self, sys_argv):
        super().__init__(sys_argv)
        self.setQuitOnLastWindowClosed(False)
        
        self.tray_icon = QtWidgets.QSystemTrayIcon()
        icon_path = os.path.join(BASE_DIR, "icon.png")
        if os.path.exists(icon_path):
            self.tray_icon.setIcon(QtGui.QIcon(icon_path))
        else:
            self.tray_icon.setIcon(self.style().standardIcon(QtWidgets.QStyle.StandardPixmap.SP_ComputerIcon))
            
        self.tray_icon.setToolTip("Process Monitor")
        
        menu = QtWidgets.QMenu()
        action_procs = menu.addAction("Show Processes")
        action_procs.triggered.connect(self.show_processes)
        
        action_logs = menu.addAction("Show Logs")
        action_logs.triggered.connect(self.show_logs)
        
        action_quit = menu.addAction("Quit")
        action_quit.triggered.connect(self.quit)
        
        self.tray_icon.setContextMenu(menu)
        self.tray_icon.show()
        
        # Windows references
        self.log_viewer = None
        self.proc_viewer = None
        
        # Connect signals
        monitor_signals.request_access.connect(self.handle_access_request)
        
    def show_processes(self):
        if not self.proc_viewer:
            self.proc_viewer = ProcessViewer()
        self.proc_viewer.show()
        self.proc_viewer.raise_()
        
    def show_logs(self):
        if not self.log_viewer:
            self.log_viewer = LogViewer()
        self.log_viewer.show()
        self.log_viewer.raise_()
        
    @QtCore.pyqtSlot(str, str, int, float, float, str)
    def handle_access_request(self, device, process_name, pid, cpu_usage, mem_usage, process_path):
        if is_allowed_forever(process_path):
            print(f"Permanent access granted for {process_name} (PID: {pid}) at {process_path}")
            allowed = True
            anomaly_score_val = detect_anomaly(cpu_usage, mem_usage, pid)
        else:
            anomaly_score = detect_anomaly(cpu_usage, mem_usage, pid)
            popup = AccessPopup(device, process_name, pid, cpu_usage, mem_usage, process_path, anomaly_score)
            result = popup.exec()
            allowed = popup.allowed
            anomaly_score_val = anomaly_score
            
        if not allowed:
            block_process(pid)
            
        log_access(device, process_name, pid, allowed, anomaly_score_val, process_path)


def analyze_network_traffic():
    def packet_callback(packet):
        if packet.haslayer(IP):
            suspicious = False
            if packet.haslayer(TCP) and packet[TCP].dport in SUSPICIOUS_PORTS:
                suspicious = True
            elif packet.haslayer(UDP) and packet[UDP].dport in SUSPICIOUS_PORTS:
                suspicious = True
            if suspicious:
                for pid in psutil.pids():
                    try:
                        p = psutil.Process(pid)
                        files = p.open_files()
                        for device in VIDEO_DEVICES + get_audio_devices():
                            if any(f.path == device for f in files):
                                process_name, p_pid, cpu_usage, mem_usage, process_path = get_process_info(device)
                                if process_name:
                                    monitor_signals.request_access.emit(device, process_name, p_pid, cpu_usage, mem_usage, process_path)
                                break
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
    # Sniffing on all interfaces
    sniff(prn=packet_callback, store=0, filter="tcp or udp")

class DeviceWatcher(pyinotify.ProcessEvent):
    def process_IN_OPEN(self, event):
        device = event.pathname
        process_name, pid, mem_usage, cpu_usage, process_path = get_process_info(device)
        if process_name:
            monitor_signals.request_access.emit(device, process_name, pid, cpu_usage, mem_usage, process_path)

def get_audio_devices():
    try:
        return [f"/dev/snd/{dev}" for dev in os.listdir("/dev/snd/") if dev.startswith("pcm")]
    except:
        return []

def start_monitoring():
    try:
        open(LOG_FILE, "a").close()
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

    print("Monitoring started in background. Running silently...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping monitor...")
        notifier.stop()

def main():
    app = TrayApp(sys.argv)
    
    # Start background monitoring
    monitor_thread = threading.Thread(target=start_monitoring, daemon=True)
    monitor_thread.start()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
