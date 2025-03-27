import sys
import psutil
import time
import numpy as np
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QWidget, QFrame, QTableWidget, QTableWidgetItem, QGraphicsDropShadowEffect, QHeaderView
from PyQt5.QtGui import QColor, QFont, QPalette
from PyQt5.QtCore import QTimer, Qt
import pyqtgraph as pg
from sklearn.ensemble import IsolationForest

class NetworkMonitorGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI-Powered Network Monitor")
        self.setGeometry(100, 100, 1600, 900)  # Increased window size
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2C3E50;
            }
            QLabel {
                color: #ECF0F1;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            QPushButton {
                border-radius: 6px;
                font-weight: bold;
                font-family: 'Segoe UI', Arial, sans-serif;
                padding: 10px;
                margin: 5px 0;
                text-transform: uppercase;
            }
            QPushButton:hover {
                opacity: 0.8;
            }
        """)
        
        self.history = []
        self.anomalies = []
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.monitoring = False
        self.prev_sent = 0
        self.prev_recv = 0

        self.initUI()
        
    def initUI(self):
        container = QWidget()
        self.setCentralWidget(container)
        main_layout = QHBoxLayout(container)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)
        
        # Sidebar Frame (Increased width)
        self.sidebar = QFrame(self)
        self.sidebar.setFixedWidth(350)  # Increased from 250 to 350
        self.sidebar.setStyleSheet("""
            QFrame {
                background-color: #34495E; 
                border-radius: 15px; 
                padding: 20px;
            }
        """)
        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setSpacing(15)
        
        # Add shadow effect to sidebar
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(20)
        shadow.setColor(QColor(0, 0, 0, 80))
        shadow.setOffset(5, 5)
        self.sidebar.setGraphicsEffect(shadow)
        
        # Status Section
        status_frame = QFrame()
        status_layout = QVBoxLayout(status_frame)
        status_layout.setSpacing(10)
        
        status_title = QLabel("Network Status")
        status_title.setStyleSheet("font-size: 18px; font-weight: bold; color: #3498DB;")
        status_layout.addWidget(status_title)
        
        self.status_label = QLabel("Status: Idle")
        self.status_label.setStyleSheet("color: #2ECC71; font-size: 16px;")
        status_layout.addWidget(self.status_label)
        
        # Traffic Section
        traffic_frame = QFrame()
        traffic_layout = QVBoxLayout(traffic_frame)
        traffic_layout.setSpacing(10)
        
        traffic_title = QLabel("Traffic")
        traffic_title.setStyleSheet("font-size: 18px; font-weight: bold; color: #3498DB;")
        traffic_layout.addWidget(traffic_title)
        
        self.sent_value = QLabel("Sent: 0 B/s")
        self.sent_value.setStyleSheet("color: #E74C3C; font-size: 14px;")
        traffic_layout.addWidget(self.sent_value)
        
        self.recv_value = QLabel("Received: 0 B/s")
        self.recv_value.setStyleSheet("color: #2980B9; font-size: 14px;")
        traffic_layout.addWidget(self.recv_value)
        
        # Control Buttons
        self.start_btn = QPushButton("Start Monitoring")
        self.start_btn.setStyleSheet("""
            background-color: #2ECC71; 
            color: white;
        """)
        self.start_btn.clicked.connect(self.start_monitoring)
        
        self.stop_btn = QPushButton("Stop Monitoring")
        self.stop_btn.setStyleSheet("""
            background-color: #E74C3C; 
            color: white;
        """)
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_monitoring)
        
        self.reset_btn = QPushButton("Reset")
        self.reset_btn.setStyleSheet("""
            background-color: #F39C12; 
            color: white;
        """)
        self.reset_btn.clicked.connect(self.reset_monitoring)
        
        # Add widgets to sidebar layout
        sidebar_layout.addWidget(status_frame)
        sidebar_layout.addWidget(traffic_frame)
        sidebar_layout.addWidget(self.start_btn)
        sidebar_layout.addWidget(self.stop_btn)
        sidebar_layout.addWidget(self.reset_btn)
        sidebar_layout.addStretch(1)
        
        # Main Content Layout (Graph + Table)
        main_content_layout = QVBoxLayout()
        
        # Graph
        self.graph_widget = pg.PlotWidget()
        self.graph_widget.setBackground("#2C3E50")
        graph_title = self.graph_widget.setTitle("Network Traffic Monitor", color="#ECF0F1", size="20pt")
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
        
        # Add shadow to graph
        graph_shadow = QGraphicsDropShadowEffect(self)
        graph_shadow.setBlurRadius(20)
        graph_shadow.setColor(QColor(0, 0, 0, 80))
        graph_shadow.setOffset(5, 5)
        self.graph_widget.setGraphicsEffect(graph_shadow)
        
        main_content_layout.addWidget(self.graph_widget)
        
        # Anomaly Table - Completely Redesigned
        self.anomaly_table = QTableWidget()
        self.anomaly_table.setColumnCount(3)
        self.anomaly_table.setHorizontalHeaderLabels(["#", "Timestamp", "Anomaly Details"])
        self.anomaly_table.setStyleSheet("""
            QTableWidget {
                background-color: #2C3E50;
                color: white;
                border-radius: 10px;
                gridline-color: #34495E;
            }
            QHeaderView::section {
                background-color: #34495E;
                color: #ECF0F1;
                padding: 10px;
                border: none;
                font-weight: bold;
                font-size: 14px;
                text-transform: uppercase;
            }
            QTableWidget::item {
                padding: 8px;
                border: 1px solid #34495E;
                color: #ECF0F1;
            }
            QTableWidget::item:selected {
                background-color: #3498DB;
                color: white;
            }
        """)
        
        # Configure table properties
        header = self.anomaly_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        
        # Configure column widths
        self.anomaly_table.setColumnWidth(0, 50)   # Index column
        self.anomaly_table.setColumnWidth(1, 150)  # Timestamp column
        self.anomaly_table.setColumnWidth(2, 300)  # Anomaly Details column
        
        # Reduce row height
        self.anomaly_table.verticalHeader().setVisible(False)
        self.anomaly_table.verticalHeader().setDefaultSectionSize(40)
        
        # Add shadow to table
        table_shadow = QGraphicsDropShadowEffect(self)
        table_shadow.setBlurRadius(20)
        table_shadow.setColor(QColor(0, 0, 0, 80))
        table_shadow.setOffset(5, 5)
        self.anomaly_table.setGraphicsEffect(table_shadow)
        
        main_content_layout.addWidget(self.anomaly_table)
        
        # Add Sidebar, Table, and Graph to Layouts
        main_layout.addWidget(self.sidebar)
        main_layout.addLayout(main_content_layout)
        
        # Timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.monitor_network)
    
    def start_monitoring(self):
        self.monitoring = True
        self.timer.start(1000)
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("Status: Monitoring")
        self.status_label.setStyleSheet("color: #2ECC71; font-size: 16px;")
    
    def stop_monitoring(self):
        self.monitoring = False
        self.timer.stop()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Status: Stopped")
        self.status_label.setStyleSheet("color: #F39C12; font-size: 16px;")
    
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
            
            # Timestamp column
            timestamp_item = QTableWidgetItem(time.strftime("%H:%M:%S"))
            timestamp_item.setTextAlignment(Qt.AlignCenter)
            
            # Anomaly Details column with more information
            anomaly_details = f"Anomalous Traffic: {self.format_bytes(value)}"
            details_item = QTableWidgetItem(anomaly_details)
            details_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            
            self.anomaly_table.setItem(row, 0, index_item)
            self.anomaly_table.setItem(row, 1, timestamp_item)
            self.anomaly_table.setItem(row, 2, details_item)
    
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
        # Reset numpy arrays
        self.sent_data = np.zeros(self.max_history)
        self.recv_data = np.zeros(self.max_history)
        
        self.history.clear()
        self.anomalies.clear()
        
        # Clear graph data
        self.sent_curve.setData(self.sent_data)
        self.recv_curve.setData(self.recv_data)
        self.anomaly_curve.setData([])
        
        self.anomaly_table.setRowCount(0)
        self.status_label.setText("Status: Idle")
        self.sent_value.setText("Sent: 0 B/s")
        self.recv_value.setText("Received: 0 B/s")
        self.prev_sent = 0
        self.prev_recv = 0

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkMonitorGUI()
    window.show()
    sys.exit(app.exec_())
