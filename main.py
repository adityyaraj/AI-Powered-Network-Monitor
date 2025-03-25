import psutil
import time
import numpy as np
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
import tkinter as tk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import threading

class NetworkMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AI-Powered Network Monitor")
        self.root.geometry("800x550")
        
        self.history = []
        self.anomaly_detector = None
        self.monitoring = False

        # Store previous values for traffic difference calculation
        self.prev_sent = 0
        self.prev_recv = 0

        # UI Elements
        self.label = tk.Label(root, text="Network Monitoring", font=("Arial", 16))
        self.label.pack()

        self.status_label = tk.Label(root, text="Status: Idle", font=("Arial", 12))
        self.status_label.pack()

        self.color_box = tk.Canvas(root, width=50, height=50, bg="green")
        self.color_box.pack()

        # Sent Bytes Box
        self.sent_frame = tk.Frame(root)
        self.sent_frame.pack()
        self.sent_label = tk.Label(self.sent_frame, text="Sent:", font=("Arial", 12))
        self.sent_label.pack(side=tk.LEFT)
        self.sent_value = tk.Label(self.sent_frame, text="0 B/s", font=("Arial", 12, "bold"), fg="red")
        self.sent_value.pack(side=tk.LEFT)

        # Received Bytes Box
        self.recv_frame = tk.Frame(root)
        self.recv_frame.pack()
        self.recv_label = tk.Label(self.recv_frame, text="Received:", font=("Arial", 12))
        self.recv_label.pack(side=tk.LEFT)
        self.recv_value = tk.Label(self.recv_frame, text="0 B/s", font=("Arial", 12, "bold"), fg="blue")
        self.recv_value.pack(side=tk.LEFT)

        self.start_btn = tk.Button(root, text="Start Monitoring", command=self.start_monitoring)
        self.start_btn.pack()

        self.stop_btn = tk.Button(root, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_btn.pack()

        # Matplotlib Figure for Graph
        self.fig, self.ax = plt.subplots(figsize=(6, 3))
        self.ax.set_title("Network Traffic")
        self.ax.set_xlabel("Time")
        self.ax.set_ylabel("Speed (Bytes per Second)")
        self.ax.legend(["Sent", "Received"])

        self.canvas = FigureCanvasTkAgg(self.fig, master=root)
        self.canvas.get_tk_widget().pack()

    def format_bytes(self, size):
        """Convert bytes to a human-readable format (KB, MB, GB)."""
        if size < 1024:
            return f"{size} B/s"
        elif size < 1024**2:
            return f"{size / 1024:.2f} KB/s"
        elif size < 1024**3:
            return f"{size / 1024**2:.2f} MB/s"
        else:
            return f"{size / 1024**3:.2f} GB/s"

    def get_network_usage(self):
        stats = psutil.net_io_counters()
        sent, recv = stats.bytes_sent, stats.bytes_recv
        
        # Calculate difference from previous reading
        sent_diff = sent - self.prev_sent
        recv_diff = recv - self.prev_recv

        # Store new values for next calculation
        self.prev_sent, self.prev_recv = sent, recv
        
        return sent_diff, recv_diff

    def train_anomaly_model(self, data):
        model = IsolationForest(contamination=0.1)
        model.fit(data)
        return model

    def update_graph(self):
        if not self.history:
            return

        history_arr = np.array(self.history)
        self.ax.clear()
        self.ax.plot(history_arr[:, 0], label="Bytes Sent", color="red")
        self.ax.plot(history_arr[:, 1], label="Bytes Received", color="blue")
        self.ax.legend()
        self.canvas.draw()

    def update_traffic_status(self, sent, recv):
        total_traffic = sent + recv

        # Update the sent and received values in the GUI
        self.sent_value.config(text=self.format_bytes(sent))
        self.recv_value.config(text=self.format_bytes(recv))

        if total_traffic < 5_000_000:  # Low Traffic
            self.color_box.config(bg="green")
            self.status_label.config(text="Status: Normal Traffic")
        elif total_traffic < 20_000_000:  # Medium Traffic
            self.color_box.config(bg="yellow")
            self.status_label.config(text="Status: Medium Traffic")
        else:  # High Traffic (Anomaly)
            self.color_box.config(bg="red")
            self.status_label.config(text="Status: High Traffic (Possible Anomaly)")

    def monitor_network(self):
        self.monitoring = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)

        while self.monitoring:
            sent, recv = self.get_network_usage()
            usage = np.array([[sent, recv]])

            self.history.append([sent, recv])
            if len(self.history) > 100:
                self.history.pop(0)

            if len(self.history) >= 20 and self.anomaly_detector is None:
                self.anomaly_detector = self.train_anomaly_model(np.array(self.history))

            if self.anomaly_detector:
                pred = self.anomaly_detector.predict(usage)
                if pred[0] == -1:
                    self.status_label.config(text="Status: Anomaly Detected!", fg="red")
                    self.color_box.config(bg="red")

            self.update_graph()
            self.update_traffic_status(sent, recv)

            time.sleep(2)

    def start_monitoring(self):
        thread = threading.Thread(target=self.monitor_network)
        thread.daemon = True
        thread.start()
        self.status_label.config(text="Status: Monitoring...")

    def stop_monitoring(self):
        self.monitoring = False
        self.status_label.config(text="Status: Stopped")
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkMonitorGUI(root)
    root.mainloop()
