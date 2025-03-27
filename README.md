# 🌐 AI-Driven Network Monitor with DDoS Detection

## Overview

This is a sophisticated network monitoring and DDoS detection application built with Python, leveraging machine learning techniques to identify potential network anomalies and security threats. The application provides real-time network traffic visualization, anomaly detection, and IP blocking capabilities.

![Network Monitor Screenshot](screenshot.png)  <!-- Replace with an actual screenshot when available -->

## 🚀 Features

- **Real-time Network Traffic Monitoring**
  - Track bytes sent and received
  - Visualize network traffic using interactive graphs
  - Monitor connection counts and traffic rates

- **Advanced Anomaly Detection**
  - Multiple machine learning models for detecting network anomalies
    - Isolation Forest
    - One-Class SVM
    - Local Outlier Factor
  - Configurable anomaly thresholds
  - Detailed anomaly logging

- **DDoS Protection**
  - Automatic detection of potential DDoS attacks
  - Cross-platform IP blocking
    - Linux (iptables)
    - macOS (pfctl)
    - Windows (Windows Firewall)
  - IP reputation and geolocation checks

- **Intuitive User Interface**
  - Dark-themed, modern design
  - Real-time traffic statistics
  - Interactive anomaly table
  - Comprehensive logging system

## 🛠 Prerequisites

- Python 3.8+
- pip package manager

## 📦 Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/network-monitor.git
cd network-monitor
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

## 📋 Requirements File (requirements.txt)
```
numpy
psutil
scikit-learn
pyqtgraph
PyQt5
ipaddress
```

## 🖥 Usage

### Starting the Application
```bash
python network_monitor.py
```

### Application Controls
- **Start Monitoring**: Begin network traffic analysis
- **Stop Monitoring**: Pause network monitoring
- **Reset**: Clear current monitoring data
- **Block Suspicious IPs**: Manually trigger IP blocking

## 🔒 Security Considerations

- Requires administrative/sudo privileges for IP blocking
- Use in controlled, authorized network environments
- Always obtain proper permissions before monitoring networks

## 🤖 Machine Learning Anomaly Detection

The application uses three advanced machine learning techniques:
1. **Isolation Forest**: Identifies anomalies by isolating outliers
2. **One-Class SVM**: Learns the boundary of normal data
3. **Local Outlier Factor**: Compares local density of data points

## 📊 Performance Metrics

- Low computational overhead
- Real-time processing
- Configurable detection sensitivity

## 🔧 Customization

Modify detection parameters in the `DDoSDetector` class:
- Adjust `history_size`
- Change `anomaly_threshold`
- Configure ML model parameters

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## ⚠️ Disclaimer

This tool is for educational and authorized network monitoring purposes only. Misuse may be illegal and unethical.

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
