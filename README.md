# 🔐 AI-Based Network Anomaly Detection System

**Developer:** Nathaniel Gborgbor  
**Institution:** Ho Technical University  
**Programme:** BTech Computer Science | Level 300  
**Specialization:** Cybersecurity & Artificial Intelligence  

---

## 📌 Project Overview
An AI-powered network anomaly detection system that uses 
Machine Learning to detect unusual network behavior and 
cyberattacks in real time. Built using the NSL-KDD dataset 
— a real-world cybersecurity benchmark dataset used by 
researchers worldwide.

---

## 🚨 Attack Types Detected
- 💀 DoS (Denial of Service) attacks
- 🕵️ Probe/Network Scanning attacks
- 🔓 R2L (Unauthorized Remote Access)
- ⬆️ U2R (Privilege Escalation)

---

## 🤖 How It Works
1. Loads real network traffic data (NSL-KDD Dataset)
2. Preprocesses and encodes network features
3. Trains an **Isolation Forest** ML model
4. Detects and flags anomalous/attack traffic
5. Visualizes results with professional graphs

---

## 🛠️ Technologies Used
| Tool | Purpose |
|---|---|
| Python 3.14 | Core programming language |
| Scikit-learn | Machine Learning (Isolation Forest) |
| Pandas & NumPy | Data processing |
| Matplotlib | Visualization |
| NSL-KDD Dataset | Real network attack data |

---

## 📊 Results
- ✅ Successfully detects real network attacks
- ✅ Trained on 125,000+ real network records
- ✅ Visualizes normal vs attack traffic clearly

---

## 🚀 How To Run
```bash
# Install dependencies
pip install numpy pandas scikit-learn matplotlib

# Run the detector
python real_anomaly_detector.py
```

---

## 🎯 Future Improvements
- [ ] Add Flask web dashboard
- [ ] Real-time network monitoring
- [ ] Email alert system
- [ ] Deep Learning model upgrade

---

## 👨🏾‍💻 About The Developer
Nathaniel Gborgbor is a Level 300 BTech Computer Science 
student at Ho Technical University, Ghana 🇬🇭, specializing 
in Cybersecurity and AI, aspiring to become a 
Chief Security Officer (CSO).
