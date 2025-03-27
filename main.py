import sys
import psutil
import time
import numpy as np
import threading
import os
import ipaddress
import socket
import subprocess
import pyqtgraph as pg
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QWidget, QFrame, QTableWidget, QTableWidgetItem, 
                             QGraphicsDropShadowEffect, QHeaderView, QTextEdit, QMessageBox)
from PyQt5.QtGui import QColor, QFont, QPalette, QIcon
from PyQt5.QtCore import QTimer, Qt, pyqtSignal, QObject, QCoreApplication
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from collections import deque

class SignalRelay(QObject):
    log_signal = pyqtSignal(str)
    alert_signal = pyqtSignal(str)

class IPAnalyzer:
    @staticmethod
    def is_private_ip(ip):
        """Check if an IP address is private"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return (
                ip_obj.is_private or 
                ip_obj.is_loopback or 
                ip_obj.is_reserved or 
                ip_obj.is_multicast
            )
        except ValueError:
            return False

    @staticmethod
    def geolocate_ip(ip):
        """Basic IP geolocation (placeholder)"""
        try:
            hostname = socket.gethostbyaddr(ip)
            return hostname[0]
        except (socket.herror, socket.gaierror):
            return "Unknown"

    @staticmethod
    def get_ip_reputation(ip):
        """Basic IP reputation check (mock implementation)"""
        suspicious_patterns = [
            'bot', 'crawler', 'spam', 'malware', 'attack', 'hack'
        ]
        
        try:
            hostname = socket.gethostbyaddr(ip)[0].lower()
            return any(pattern in hostname for pattern in suspicious_patterns)
        except (socket.herror, socket.gaierror):
            return False

class DDoSDetector:
    def __init__(self, signal_relay, history_size=100, anomaly_threshold=3):
        self.history = deque(maxlen=history_size)
        self.anomalies = []
        self.prev_sent = 0
        self.prev_recv = 0
        self.prev_sent_packets = 0
        self.prev_recv_packets = 0
        self.anomaly_count = 0
        self.anomaly_threshold = anomaly_threshold  
        self.running = False  
        self.signal_relay = signal_relay
        self.blocked_ips = set()

        # ML Models
        self.iso_forest = IsolationForest(contamination=0.05)
        self.svm_detector = OneClassSVM(nu=0.05)
        self.lof_detector = LocalOutlierFactor(n_neighbors=20, novelty=True)

    def monitor_network(self):
        net_io = psutil.net_io_counters()
        conn_count = len(psutil.net_connections())  
        sent = net_io.bytes_sent
        recv = net_io.bytes_recv
        packets_sent = net_io.packets_sent
        packets_recv = net_io.packets_recv

        sent_rate = sent - self.prev_sent
        recv_rate = recv - self.prev_recv
        packet_rate = (packets_sent - self.prev_sent_packets) + (packets_recv - self.prev_recv_packets)

        self.prev_sent = sent
        self.prev_recv = recv
        self.prev_sent_packets = packets_sent
        self.prev_recv_packets = packets_recv

        # Update history
        self.history.append([sent_rate, recv_rate, packet_rate, conn_count])

        # Update log
        self.signal_relay.log_signal.emit(f"📡 Monitoring: Sent={sent_rate}, Recv={recv_rate}, Packets={packet_rate}, Conns={conn_count}")
        return sent_rate, recv_rate, packet_rate, conn_count

    def detect_ddos(self):
        if len(self.history) < 10:
            return None

        X = np.array(self.history)

        # Fit models
        self.iso_forest.fit(X)
        self.svm_detector.fit(X)
        self.lof_detector.fit(X)

        # Predict anomalies
        iso_preds = self.iso_forest.predict(X)
        svm_preds = self.svm_detector.predict(X)
        lof_preds = self.lof_detector.predict(X)

        # Mark anomalies
        self.anomalies = [(i, X[i]) for i in range(len(X)) if iso_preds[i] == -1 or svm_preds[i] == -1 or lof_preds[i] == -1]

        if len(self.anomalies) > 0:
            self.anomaly_count += 1
            self.signal_relay.log_signal.emit(f"⚠ DDoS Alert: {len(self.anomalies)} anomalies detected!")
            self.log_anomalies()

            # Take action
            if self.anomaly_count >= self.anomaly_threshold:
                return self.detect_and_block_suspicious_ips()

        return None

    def detect_and_block_suspicious_ips(self):
        # Get all active network connections
        connections = psutil.net_connections()
        suspicious_ips = set()

        for conn in connections:
            if conn.status == 'ESTABLISHED' and conn.raddr:
                remote_ip = conn.raddr.ip

                # Skip private/internal IPs
                if IPAnalyzer.is_private_ip(remote_ip):
                    continue

                # Check IP reputation
                if IPAnalyzer.get_ip_reputation(remote_ip):
                    suspicious_ips.add(remote_ip)

        # Block suspicious IPs
        for ip in suspicious_ips:
            if ip not in self.blocked_ips:
                self.block_ip(ip)
                self.blocked_ips.add(ip)

        if suspicious_ips:
            blocking_msg = f"🚫 Blocked {len(suspicious_ips)} suspicious IPs: {', '.join(suspicious_ips)}"
            self.signal_relay.log_signal.emit(blocking_msg)
            self.signal_relay.alert_signal.emit(blocking_msg)
            return list(suspicious_ips)

        return None

    def block_ip(self, ip):
        """Block an IP using system firewall"""
        try:
            # Cross-platform IP blocking
            if sys.platform.startswith('linux'):
                subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            elif sys.platform == 'darwin':  # macOS
                subprocess.run(['sudo', 'pfctl', '-t', 'blocked', '-T', 'add', ip], check=True)
            elif sys.platform == 'win32':  # Windows
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 
                                f'name=Block {ip}', 'dir=in', 
                                f'action=block', f'remoteip={ip}'], check=True)
        except subprocess.CalledProcessError as e:
            self.signal_relay.log_signal.emit(f"❌ Error blocking IP {ip}: {e}")

    def log_anomalies(self):
        with open("ddos_logs.txt", "a") as log_file:
            for anomaly in self.anomalies:
                log_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Anomaly Detected: {anomaly}\n")

class NetworkMonitorGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        # Ensure complete window closure
        self.setAttribute(Qt.WA_DeleteOnClose)
        
        self.setWindowTitle("AI-Powered Network Monitor with DDoS Detection")
        
        # Full-screen handling
        screen = QApplication.primaryScreen().geometry()
        self.setGeometry(screen)
        
        # Application icon
        self.setWindowIcon(QIcon('network_icon.png'))  # Create a network icon if you want
        
        self.history = []
        self.anomalies = []
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.monitoring = False
        self.prev_sent = 0
        self.prev_recv = 0

        # Signal Relay for Thread Communication
        self.signal_relay = SignalRelay()
        self.signal_relay.log_signal.connect(self.log_message)
        self.signal_relay.alert_signal.connect(self.show_alert)

        # DDoS Detector
        self.ddos_detector = DDoSDetector(self.signal_relay)
        self.ddos_monitoring_thread = None
        self.anomaly_timestamps = {}

        self.initUI()
        
    def initUI(self):
        # Global background color
        global_bg_color = "#1E2633"  # Deep dark blue-gray
        sidebar_bg_color = "#263340"  # Slightly lighter than global background
        
        # Set application-wide style
        self.setStyleSheet(f"""
            QWidget {{
                background-color: {global_bg_color};
                color: #FFFFFF;
            }}
        """)
        
        # Create main container widget
        container = QWidget()
        self.setCentralWidget(container)
        main_layout = QHBoxLayout(container)
        main_layout.setContentsMargins(5, 5, 5, 5)  # Minimal margins
        main_layout.setSpacing(5)  # Minimal spacing
        
        # Sidebar Frame 
        self.sidebar = QFrame(self)
        self.sidebar.setFixedWidth(320)  # Slightly narrower
        self.sidebar.setStyleSheet(f"""
            QFrame {{
                background-color: {sidebar_bg_color}; 
                border-radius: 10px; 
                padding: 10px;
            }}
        """)
        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setSpacing(8)  # Tight spacing
        sidebar_layout.setContentsMargins(5, 5, 5, 5)
        
        # Control Buttons Colors
        button_colors = {
            "start": "#2ECC71",     # Bright Green
            "stop": "#E74C3C",      # Bright Red
            "reset": "#F39C12",     # Bright Orange
            "block": "#9B59B6"      # Bright Purple
        }
        
        # Button Style Template
        button_style = """
            QPushButton {{
                background-color: {color}; 
                color: white;
                border-radius: 5px;
                padding: 8px;
                font-size: 12px;
                font-weight: bold;
                text-transform: uppercase;
            }}
            QPushButton:hover {{
                background-color: {hover_color};
            }}
            QPushButton:disabled {{
                background-color: #7F8C8D;
            }}
        """
        
        # Status and Traffic Labels
        status_style = "color: #3498DB; font-size: 24px; font-weight: bold;"
        value_style = "color: #ECF0F1; font-size: 22px;"
        
        # Status Section
        status_title = QLabel("Network Status")
        status_title.setStyleSheet(status_style)
        sidebar_layout.addWidget(status_title)
        
        self.status_label = QLabel("Status: Idle")
        self.status_label.setStyleSheet("color: #2ECC71; font-size: 22px;")
        sidebar_layout.addWidget(self.status_label)
        
        # Traffic Section
        traffic_title = QLabel("Traffic")
        traffic_title.setStyleSheet(status_style)
        sidebar_layout.addWidget(traffic_title)
        
        self.sent_value = QLabel("Sent: 0 B/s")
        self.sent_value.setStyleSheet("color: #E74C3C; font-size: 21px;")
        sidebar_layout.addWidget(self.sent_value)
        
        self.recv_value = QLabel("Received: 0 B/s")
        self.recv_value.setStyleSheet("color: #3498DB; font-size: 21px;")
        sidebar_layout.addWidget(self.recv_value)
        
        # Buttons with dynamic styling
        self.start_btn = QPushButton("Start Monitoring")
        self.start_btn.setStyleSheet(button_style.format(
            color=button_colors["start"], 
            hover_color="#27AE60"
        ))
        self.start_btn.clicked.connect(self.start_monitoring)
        
        self.stop_btn = QPushButton("Stop Monitoring")
        self.stop_btn.setStyleSheet(button_style.format(
            color=button_colors["stop"], 
            hover_color="#C0392B"
        ))
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_monitoring)
        
        self.reset_btn = QPushButton("Reset")
        self.reset_btn.setStyleSheet(button_style.format(
            color=button_colors["reset"], 
            hover_color="#D35400"
        ))
        self.reset_btn.clicked.connect(self.reset_monitoring)
        
        self.block_ips_btn = QPushButton("Block Suspicious IPs")
        self.block_ips_btn.setStyleSheet(button_style.format(
            color=button_colors["block"], 
            hover_color="#8E44AD"
        ))
        self.block_ips_btn.clicked.connect(self.block_suspicious_ips)
        
        # Add buttons to sidebar
        sidebar_layout.addWidget(self.start_btn)
        sidebar_layout.addWidget(self.stop_btn)
        sidebar_layout.addWidget(self.reset_btn)
        sidebar_layout.addWidget(self.block_ips_btn)
        
        # Log View
        self.log_view = QTextEdit()
        self.log_view.setMaximumHeight(150)  # Reduced height
        self.log_view.setReadOnly(True)
        self.log_view.setStyleSheet("""
            background-color: #2C3E50;
            color: #ECF0F1;
            font-family: 'Courier New', monospace;
            font-size: 10px;
            border-radius: 5px;
        """)
        
        sidebar_layout.addWidget(QLabel("Logs:"))
        sidebar_layout.addWidget(self.log_view)
        sidebar_layout.addStretch(1)
        
        # Main Content Layout
        main_content_layout = QVBoxLayout()
        main_content_layout.setSpacing(5)
        main_content_layout.setContentsMargins(0, 0, 0, 0)
        
        # Graph 
        self.graph_widget = pg.PlotWidget()
        self.graph_widget.setBackground("#2C3E50")
        self.graph_widget.setTitle("Network Traffic Monitor", color="#ECF0F1", size="14pt")
        self.graph_widget.setLabel("left", "Speed (Bytes per Second)", color="#ECF0F1")
        self.graph_widget.setLabel("bottom", "Time", color="#ECF0F1")
        self.graph_widget.showGrid(x=True, y=True, alpha=0.3)
        self.graph_widget.addLegend()
        
        # Create data arrays for plotting
        self.max_history = 100
        self.sent_data = np.zeros(self.max_history)
        self.recv_data = np.zeros(self.max_history)
        
        # Updated plot method to use numpy arrays
        self.sent_curve = self.graph_widget.plot(self.sent_data, pen=pg.mkPen(color="#E74C3C", width=3), name="Bytes Sent")
        self.recv_curve = self.graph_widget.plot(self.recv_data, pen=pg.mkPen(color="#3498DB", width=3), name="Bytes Received")
        self.anomaly_curve = self.graph_widget.plot(pen=None, symbol='o', symbolSize=10, symbolBrush=QColor(255, 165, 0), name="Anomalies")
        
        main_content_layout.addWidget(self.graph_widget)
        
        # Anomaly Table
        self.anomaly_table = QTableWidget()
        self.anomaly_table.setColumnCount(3)
        self.anomaly_table.setHorizontalHeaderLabels(["#", "Timestamp", "Anomaly Details"])
        self.anomaly_table.setStyleSheet("""
            QTableWidget {
                background-color: #2C3E50;
                color: #ECF0F1;
                gridline-color: #34495E;
                border-radius: 5px;
            }
            QHeaderView::section {
                background-color: #34495E;
                color: #ECF0F1;
                padding: 5px;
                border: none;
                font-weight: bold;
                font-size: 11px;
                text-transform: uppercase;
            }
            QTableWidget::item {
                padding: 5px;
                border: 1px solid #34495E;
                color: #ECF0F1;
            }
        """)
        
        header = self.anomaly_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        
        self.anomaly_table.verticalHeader().setVisible(False)
        self.anomaly_table.verticalHeader().setDefaultSectionSize(30)
        
        main_content_layout.addWidget(self.anomaly_table)
        
        # Add Sidebar and Main Content
        main_layout.addWidget(self.sidebar)
        main_layout.addLayout(main_content_layout)
        
        # Set layout stretch to balance sidebar and main content
        main_layout.setStretch(0, 1)  # Sidebar
        main_layout.setStretch(1, 3)  # Main content
        
        # Timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.monitor_network)
    
    def log_message(self, message):
        self.log_view.append(message)
    
    def show_alert(self, message):
        QMessageBox.warning(self, "Network Security Alert", message)
    
    def start_monitoring(self):
        self.monitoring = True
        self.timer.start(1000)
        self.ddos_monitoring_thread = threading.Thread(target=self.run_ddos_detection)
        self.ddos_monitoring_thread.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("Status: Monitoring")
        self.status_label.setStyleSheet("color: #2ECC71; font-size: 16px;")
    
    def stop_monitoring(self):
        self.monitoring = False
        self.timer.stop()
        self.ddos_detector.running = False
        if self.ddos_monitoring_thread:
            self.ddos_monitoring_thread.join()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Status: Stopped")
        self.status_label.setStyleSheet("color: #F39C12; font-size: 16px;")
    
    def run_ddos_detection(self):
        self.ddos_detector.running = True
        while self.monitoring:
            result = self.ddos_detector.detect_ddos()
            if result:
                self.update_anomaly_table(result)
            time.sleep(2)
    
    def block_suspicious_ips(self):
        self.ddos_detector.detect_and_block_suspicious_ips()
    
    def monitor_network(self):
        net_io = psutil.net_io_counters()
        sent = net_io.bytes_sent
        recv = net_io.bytes_recv
        sent_rate = sent - self.prev_sent
        recv_rate = recv - self.prev_recv
        self.prev_sent = sent
        self.prev_recv = recv
        
        self.sent_value.setText(f"Sent: {self.format_bytes(sent_rate)}")
        self.recv_value.setText(f"Received: {self.format_bytes(recv_rate)}")
        
        # Update numpy arrays by shifting and adding new data
        self.sent_data = np.roll(self.sent_data, -1)
        self.recv_data = np.roll(self.recv_data, -1)
        self.sent_data[-1] = sent_rate
        self.recv_data[-1] = recv_rate
        
        # Update history list for anomaly detection
        if len(self.history) >= 100:
            self.history.pop(0)
        self.history.append([sent_rate, recv_rate])
        
        if len(self.history) > 10:
            X = np.array(self.history)
            self.anomaly_detector.fit(X)  # Train the model
            preds = self.anomaly_detector.predict(X)
            self.anomalies = [(i, X[i][0]) for i in range(len(preds)) if preds[i] == -1]

        self.update_graph()
    
    def update_graph(self):
        # Update curves with numpy arrays
        self.sent_curve.setData(self.sent_data)
        self.recv_curve.setData(self.recv_data)
        
        if self.anomalies:
            x_vals, y_vals = zip(*self.anomalies) if self.anomalies else ([], [])
            self.anomaly_curve.setData(x_vals, y_vals)
        
        self.update_table()

    def update_table(self):
        self.anomaly_table.setRowCount(len(self.anomalies))
        
        for row, (index, value) in enumerate(self.anomalies):
            # Index column
            index_item = QTableWidgetItem(str(row + 1))
            index_item.setTextAlignment(Qt.AlignCenter)
            
            # Use the original timestamp for this specific anomaly
            # If no timestamp exists, create one
            if index not in self.anomaly_timestamps:
                self.anomaly_timestamps[index] = time.strftime("%Y-%m-%d %H:%M:%S")
            
            timestamp_item = QTableWidgetItem(self.anomaly_timestamps[index])
            timestamp_item.setTextAlignment(Qt.AlignCenter)
            
            # Detailed anomaly information
            anomaly_details = f"Anomalous Traffic: {self.format_bytes(value)}"
            details_item = QTableWidgetItem(anomaly_details)
            details_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            
            # Set items in the table
            self.anomaly_table.setItem(row, 0, index_item)
            self.anomaly_table.setItem(row, 1, timestamp_item)
            self.anomaly_table.setItem(row, 2, details_item)
        
        # Scroll to the bottom to show the latest anomalies
        self.anomaly_table.scrollToBottom()

    def update_anomaly_table(self, anomalies):
        for anomaly in anomalies:
            # Create a unique identifier for this anomaly
            # Depending on what 'anomaly' contains, you might need to adjust this
            anomaly_id = hash(str(anomaly))
            
            # Only create a timestamp if it doesn't exist
            if anomaly_id not in self.anomaly_timestamps:
                self.anomaly_timestamps[anomaly_id] = time.strftime("%Y-%m-%d %H:%M:%S")
            
            rowPosition = self.anomaly_table.rowCount()
            self.anomaly_table.insertRow(rowPosition)
            
            # Index
            index_item = QTableWidgetItem(str(rowPosition + 1))
            index_item.setTextAlignment(Qt.AlignCenter)
            
            # Use the original timestamp
            timestamp_item = QTableWidgetItem(self.anomaly_timestamps[anomaly_id])
            timestamp_item.setTextAlignment(Qt.AlignCenter)
            
            # Anomaly Details
            details_item = QTableWidgetItem(f"DDoS Anomaly: {anomaly}")
            details_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            
            # Set the items in the table
            self.anomaly_table.setItem(rowPosition, 0, index_item)
            self.anomaly_table.setItem(rowPosition, 1, timestamp_item)
            self.anomaly_table.setItem(rowPosition, 2, details_item)
        
        # Scroll to the bottom to show the latest anomalies
        self.anomaly_table.scrollToBottom()


    
    def format_bytes(self, size):
        if size < 1024:
            return f"{size} B/s"
        elif size < 1024**2:
            return f"{size / 1024:.2f} KB/s"
        elif size < 1024**3:
            return f"{size / 1024**2:.2f} MB/s"
        else:
            return f"{size / 1024**3:.2f} GB/s"
    
    def reset_monitoring(self):
        self.anomaly_table.setRowCount(0)
        
        # Reset anomaly timestamps
        self.anomaly_timestamps.clear()

        # Clear the entire table
        self.anomaly_table.setRowCount(0)
        
        # Reset other monitoring-related data
        self.sent_data = np.zeros(self.max_history)
        self.recv_data = np.zeros(self.max_history)
        
        self.history.clear()
        self.anomalies.clear()
        
        # Clear graph data
        self.sent_curve.setData(self.sent_data)
        self.recv_curve.setData(self.recv_data)
        self.anomaly_curve.setData([])
        
        self.log_view.clear()
        self.status_label.setText("Status: Idle")
        self.sent_value.setText("Sent: 0 B/s")
        self.recv_value.setText("Received: 0 B/s")
        self.prev_sent = 0
        self.prev_recv = 0
    
    def closeEvent(self, event):
        """
        Override close event to ensure complete application shutdown
        """
        reply = QMessageBox.question(
            self, 'Close Confirmation', 
            "Are you sure you want to exit the Network Monitor?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            # Stop monitoring threads
            if hasattr(self, 'monitoring'):
                self.monitoring = False
            if hasattr(self, 'ddos_monitoring_thread'):
                self.ddos_monitoring_thread.join(timeout=2)
            
            # Close all windows and exit
            QCoreApplication.instance().quit()
            event.accept()
        else:
            event.ignore()

def main():
    app = QApplication(sys.argv)
    
    # Global exception handler
    def exception_hook(exctype, value, traceback):
        print(f"Unhandled exception: {exctype.__name__}: {value}")
        sys.__excepthook__(exctype, value, traceback)
        QApplication.quit()
    
    sys.excepthook = exception_hook
    
    window = NetworkMonitorGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
