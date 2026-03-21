# ============================================
# AI-Based Network Anomaly Detection System
# Developer: Nathaniel Gborgbor
# Institution: Ho Technical University
# Level: 300 | BTech Computer Science
# Goal: Detect unusual network behavior using ML
# ============================================

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt

# ---- STEP 1: Generate Simulated Network Data ----
print("Generating network traffic data...")

np.random.seed(42)

# Normal network traffic (900 samples)
normal_traffic = np.random.normal(loc=50, scale=5, size=(900, 2))

# Anomalous network traffic (100 samples - attacks!)
anomalous_traffic = np.random.uniform(low=80, high=120, size=(100, 2))

# Combine normal and anomalous data
data = np.vstack([normal_traffic, anomalous_traffic])

# Create a DataFrame
df = pd.DataFrame(data, columns=["packet_size", "request_rate"])

print(f"Total records: {len(df)}")
print(f"Sample data:\n{df.head()}")

# ---- STEP 2: Train AI Model ----
print("\nTraining AI Anomaly Detection Model...")

model = IsolationForest(contamination=0.1, random_state=42)
model.fit(df)

# ---- STEP 3: Predict Anomalies ----
df["anomaly"] = model.predict(df)
# 1 = Normal, -1 = Anomaly
df["status"] = df["anomaly"].apply(lambda x: "NORMAL" if x == 1 else "⚠️ ANOMALY DETECTED")

# ---- STEP 4: Show Results ----
print("\n===== DETECTION RESULTS =====")
print(f"Normal traffic records: {len(df[df['anomaly'] == 1])}")
print(f"Anomalies detected: {len(df[df['anomaly'] == -1])}")
print("\nSample anomalies found:")
print(df[df['anomaly'] == -1].head())

# ---- STEP 5: Visualize Results ----
print("\nGenerating visualization...")

plt.figure(figsize=(10, 6))

# Plot normal traffic
normal = df[df["anomaly"] == 1]
plt.scatter(normal["packet_size"], normal["request_rate"],
            c="green", label="Normal Traffic", alpha=0.5, s=20)

# Plot anomalies
anomalies = df[df["anomaly"] == -1]
plt.scatter(anomalies["packet_size"], anomalies["request_rate"],
            c="red", label="⚠️ Anomaly", alpha=0.9, s=50, marker="X")

plt.title("AI-Based Network Anomaly Detection System\nDeveloper: Nathaniel Gborgbor | Ho Technical University")
plt.xlabel("Packet Size")
plt.ylabel("Request Rate")
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.savefig("anomaly_detection_result.png")
plt.show()

print("\n✅ Done! Results saved as 'anomaly_detection_result.png'")
print("🔐 Anomaly Detection Complete - Nathaniel Gborgbor | CSO in the making! 💪🏾")


## 👣 Now Run It!

