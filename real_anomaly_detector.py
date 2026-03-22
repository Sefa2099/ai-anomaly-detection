# ============================================
# AI-Based Network Anomaly Detection System
# REAL WORLD VERSION - NSL-KDD Dataset
# Developer: Nathaniel Gborgbor
# Institution: Ho Technical University
# Level: 300 | BTech Computer Science
# Supervisor: Claude (Anthropic)
# ============================================

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
import matplotlib.pyplot as plt
import warnings
warnings.filterwarnings('ignore')

# ---- STEP 1: Load Real NSL-KDD Dataset ----
print("Loading real NSL-KDD network attack dataset...")

# Column names for NSL-KDD dataset
columns = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
    'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
    'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
    'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
    'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate', 'attack_type', 'difficulty'
]

# Load the dataset
df = pd.read_csv('KDDTrain+.txt', names=columns)

print(f"✅ Dataset loaded successfully!")
print(f"Total records: {len(df)}")
print(f"\nAttack types found in dataset:")
print(df['attack_type'].value_counts().head(10))

# ---- STEP 2: Prepare Data ----
print("\nPreparing data for AI model...")

# Label attack types
df['label'] = df['attack_type'].apply(
    lambda x: 'NORMAL' if x == 'normal' else 'ATTACK'
)

print(f"\nNormal traffic records: {len(df[df['label'] == 'NORMAL'])}")
print(f"Attack records: {len(df[df['label'] == 'ATTACK'])}")

# Encode categorical columns
le = LabelEncoder()
df['protocol_type'] = le.fit_transform(df['protocol_type'])
df['service'] = le.fit_transform(df['service'])
df['flag'] = le.fit_transform(df['flag'])

# Select features for ML model
features = [
    'duration', 'protocol_type', 'service', 'flag',
    'src_bytes', 'dst_bytes', 'hot', 'num_failed_logins',
    'logged_in', 'num_compromised', 'count', 'srv_count',
    'serror_rate', 'rerror_rate', 'same_srv_rate', 'diff_srv_rate'
]

X = df[features]

# ---- STEP 3: Train AI Model ----
print("\nTraining AI Anomaly Detection Model on real data...")

model = IsolationForest(
    contamination=0.3,
    random_state=42,
    n_estimators=100
)
model.fit(X)

# ---- STEP 4: Predict Anomalies ----
print("Detecting anomalies...")
df['prediction'] = model.predict(X)
df['status'] = df['prediction'].apply(
    lambda x: 'NORMAL' if x == 1 else '⚠️ ATTACK DETECTED'
)

# ---- STEP 5: Results ----
print("\n" + "="*50)
print("       ANOMALY DETECTION RESULTS")
print("="*50)
print(f"✅ Normal traffic detected: {len(df[df['prediction'] == 1])}")
print(f"🚨 Attacks detected: {len(df[df['prediction'] == -1])}")
print(f"📊 Detection rate: {round(len(df[df['prediction'] == -1])/len(df)*100, 2)}%")

# Show sample attacks detected
print("\n🚨 Sample Attacks Detected:")
attacked = df[df['prediction'] == -1][['attack_type', 'protocol_type', 'src_bytes', 'status']].head(10)
print(attacked.to_string())

# ---- STEP 6: Visualization ----
print("\nGenerating professional visualization...")

fig, axes = plt.subplots(1, 2, figsize=(14, 6))
fig.suptitle(
    'AI-Based Network Anomaly Detection System\nDeveloper: Nathaniel Gborgbor | Ho Technical University',
    fontsize=13, fontweight='bold'
)

# Plot 1: Scatter plot
normal = df[df['prediction'] == 1]
anomalies = df[df['prediction'] == -1]

axes[0].scatter(
    normal['src_bytes'], normal['dst_bytes'],
    c='green', alpha=0.3, s=10, label='Normal Traffic'
)
axes[0].scatter(
    anomalies['src_bytes'], anomalies['dst_bytes'],
    c='red', alpha=0.6, s=20, marker='X', label='⚠️ Attack Detected'
)
axes[0].set_title('Network Traffic Analysis')
axes[0].set_xlabel('Source Bytes')
axes[0].set_ylabel('Destination Bytes')
axes[0].legend()
axes[0].grid(True)

# Plot 2: Attack type distribution
attack_counts = df[df['label'] == 'ATTACK']['attack_type'].value_counts().head(8)
axes[1].bar(attack_counts.index, attack_counts.values, color='red', alpha=0.7)
axes[1].set_title('Top Attack Types in Dataset')
axes[1].set_xlabel('Attack Type')
axes[1].set_ylabel('Count')
axes[1].tick_params(axis='x', rotation=45)
axes[1].grid(True, axis='y')

plt.tight_layout()
plt.savefig('real_anomaly_detection_result.png', dpi=150)
plt.show()

print("\n✅ Results saved as 'real_anomaly_detection_result.png'")
print("🔐 Real World Anomaly Detection Complete!")
print("💪🏾 Nathaniel Gborgbor | CSO in the making! 🇬🇭")