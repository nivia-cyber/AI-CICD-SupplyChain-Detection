import streamlit as st
import json
import os
import pandas as pd

st.set_page_config(page_title="AI DevSecOps Dashboard", layout="wide")

st.title("🔐 AI DevSecOps Security Dashboard")

# Check if report exists
if not os.path.exists("security_report.json"):
    st.warning("No security report found. Run pipeline first.")
    st.stop()

# Load report
with open("security_report.json", "r") as f:
    report = json.load(f)

# -----------------------------
# Status Indicator
# -----------------------------
status = report.get("build_status", "UNKNOWN")

if status == "CLEAN":
    st.success("🟢 BUILD STATUS: CLEAN")
elif status == "COMPROMISED":
    st.error("🔴 BUILD STATUS: COMPROMISED")
else:
    st.warning("⚠️ Status Unknown")

# -----------------------------
# Metrics Section
# -----------------------------
col1, col2, col3 = st.columns(3)

col1.metric("📦 File Size", report.get("size", "N/A"))
col2.metric("📊 Entropy", round(report.get("entropy", 0), 4))
col3.metric("🚨 Suspicious Count", report.get("suspicious_count", 0))

st.divider()

# -----------------------------
# Detailed Information
# -----------------------------
st.subheader("Build Information")

st.write(f"**Timestamp:** {report.get('timestamp')}")
st.write(f"**Artifact Analyzed:** {report.get('artifact_analyzed')}")
st.write(f"**Model SHA256:** {report.get('model_sha256')}")

st.divider()

# -----------------------------
# Entropy Visualization
# -----------------------------
st.subheader("Entropy Visualization")

entropy_value = report.get("entropy", 0)

df = pd.DataFrame({
    "Metric": ["Entropy"],
    "Value": [entropy_value]
})

st.bar_chart(df.set_index("Metric"))

# -----------------------------
# Security Interpretation
# -----------------------------
st.subheader("Security Interpretation")

if entropy_value > 7:
    st.warning("High entropy detected. Possible packed or obfuscated file.")
else:
    st.info("Entropy within normal range.")