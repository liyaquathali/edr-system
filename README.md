# **Endpoint Detection and Response (EDR) System** 🛡️  

## **Overview**  
The **Endpoint Detection and Response (EDR) System** is a Python-based project designed to monitor system activities and provide real-time alerts for suspicious behavior. It includes features such as process monitoring, file integrity checks, and network traffic analysis, offering a comprehensive approach to enhancing endpoint security.  

---

## **Features**  
- **Process Monitoring**: Identifies high CPU usage to detect potential threats.  
- **File Integrity Monitoring**: Validates file hashes to ensure no unauthorized modifications.  
- **Network Monitoring**: Analyzes network traffic for suspicious connections.  
- **Real-Time Alerts**: Provides immediate notifications for unusual activities.  
- **Expandable Architecture**: Designed for easy addition of new features like machine learning and graphical interfaces.  

---

## **Technologies Used**  
- **Programming Language**: Python  
- **Libraries**:  
  - [`psutil`](https://pypi.org/project/psutil/) for process monitoring.  
  - [`hashlib`](https://docs.python.org/3/library/hashlib.html) for file hashing.  
  - [`Scapy`](https://scapy.net/) for network packet sniffing.  
- **Platform Requirements**:  
  - Python 3.9+  
  - Npcap (Windows) for network sniffing.  

---

## **Getting Started**  

### **Prerequisites**  
1. Install Python 3.9 or higher.  
2. Install required Python libraries:  
   ```bash
   pip install psutil scapy

