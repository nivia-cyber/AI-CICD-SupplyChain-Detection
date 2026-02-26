import streamlit as st
import json
import os
import pandas as pd

st.set_page_config(page_title="AI DevSecOps Dashboard", layout="wide")

st.title("🔐 AI DevSecOps Security Dashboard")

# -----------------------------
# Check if report exists
# -----------------------------
if not os.path.exists("security_report.json"):
    st.warning("No security report found. Run pipeline first.")
    st.stop()

# -----------------------------
# Load report
# -----------------------------
with open("security_report.json", "r") as f:
    report = json.load(f)

# -----------------------------
# Automated Test Results
# -----------------------------
st.subheader("🧪 Automated Security Validation")

clean_result = report.get("clean_test", "UNKNOWN")
comp_result = report.get("compromised_test", "UNKNOWN")

colA, colB = st.columns(2)

with colA:
    if clean_result == "CLEAN":
        st.success("🟢 Clean Build Test: PASS")
    else:
        st.error("❌ Clean Build Test: FAIL")

with colB:
    if comp_result == "COMPROMISED":
        st.success("🔴 Compromised Build Detection: PASS")
    else:
        st.error("❌ Compromised Build Detection: FAIL")

st.divider()

# -----------------------------
# Overall Status
# -----------------------------
st.subheader("📊 Overall Security Status")

if clean_result == "CLEAN" and comp_result == "COMPROMISED":
    st.success("✅ Model is functioning correctly.")
else:
    st.error("🚨 Model validation failed. Detection logic issue.")

st.divider()

# -----------------------------
# Metrics Section
# -----------------------------
st.subheader("📈 Feature Metrics (Last Clean Test)")

col1, col2, col3 = st.columns(3)

col1.metric("📦 File Size", report.get("size", "N/A"))
col2.metric("📊 Entropy", round(report.get("entropy", 0), 4))
col3.metric("🚨 Suspicious Count", report.get("suspicious_count", 0))

st.divider()

# -----------------------------
# Detailed Information
# -----------------------------
st.subheader("📝 Build Information")

st.write(f"**Timestamp:** {report.get('timestamp')}")
st.write(f"**Model SHA256:** {report.get('model_sha256')}")

st.divider()

# -----------------------------
# Entropy Visualization
# -----------------------------
st.subheader("📊 Entropy Visualization")

entropy_value = report.get("entropy", 0)

df = pd.DataFrame({
    "Metric": ["Entropy"],
    "Value": [entropy_value]
})

st.bar_chart(df.set_index("Metric"))

st.divider()

# -----------------------------
# Security Interpretation
# -----------------------------
st.subheader("🧠 Security Interpretation")

if entropy_value > 7:
    st.warning("High entropy detected. Possible packed or obfuscated file.")
else:
    st.info("Entropy within normal range.")

st.markdown("---")
st.caption("AI-Powered DevSecOps Supply Chain Monitoring System")