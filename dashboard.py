import streamlit as st
import json
import os
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from streamlit_autorefresh import st_autorefresh

# --------------------------------------------------
# PAGE CONFIG
# --------------------------------------------------
st.set_page_config(page_title="AI DevSecOps Supply Chain", layout="wide")

# --------------------------------------------------
# AUTO REFRESH
# --------------------------------------------------
st_autorefresh(interval=3000, key="refresh")

# --------------------------------------------------
# DARK THEME
# --------------------------------------------------
st.markdown("""
<style>
body { background-color: #0f172a; color: #e2e8f0; }
.main { background-color: #0f172a; }
h1 { color: #00f5d4; }
h2, h3 { color: #38bdf8; }
</style>
""", unsafe_allow_html=True)

st.title("🛡 AI-Driven CI/CD Supply Chain Threat Detection")

# --------------------------------------------------
# LOAD DATA
# --------------------------------------------------
if not os.path.exists("security_report.json"):
    st.warning("Run pipeline.py first to generate security_report.json.")
    st.stop()

with open("security_report.json", "r") as f:
    data = json.load(f)

# Support both single object and list history
if not isinstance(data, list):
    data = [data]

df = pd.DataFrame(data)
df["timestamp"] = pd.to_datetime(df["timestamp"])

latest_event = df.iloc[-1]

risk_score = latest_event.get("risk_score", 0)
severity = latest_event.get("severity", "Minimal")
mitre_list = latest_event.get("mitre_techniques", [])
mitre_count = len(mitre_list)

# --------------------------------------------------
# KPI SECTION
# --------------------------------------------------
col1, col2, col3 = st.columns(3)
col1.metric("⚠ Risk Score", risk_score)
col2.metric("🚨 Severity", severity)
col3.metric("🎯 MITRE Techniques", mitre_count)

st.caption(f"Last Event: {latest_event['timestamp']}")
st.divider()

# --------------------------------------------------
# RISK GAUGE
# --------------------------------------------------
st.subheader("📊 Threat Risk Indicator")

gauge = go.Figure(go.Indicator(
    mode="gauge+number",
    value=risk_score,
    gauge={
        "axis": {"range": [0, 100]},
        "bar": {"color": "#ff006e"},
        "steps": [
            {"range": [0, 30], "color": "#06d6a0"},
            {"range": [30, 60], "color": "#ffd166"},
            {"range": [60, 85], "color": "#f77f00"},
            {"range": [85, 100], "color": "#d00000"},
        ],
    },
))

st.plotly_chart(gauge, use_container_width=True)
st.divider()

# --------------------------------------------------
# RISK TIMELINE
# --------------------------------------------------
st.subheader("📈 Risk Timeline")

timeline = px.line(
    df,
    x="timestamp",
    y="risk_score",
    markers=True,
    color_discrete_sequence=["#00f5d4"]
)

timeline.update_layout(
    plot_bgcolor="#0f172a",
    paper_bgcolor="#0f172a",
    font_color="white"
)

st.plotly_chart(timeline, use_container_width=True)
st.divider()

# --------------------------------------------------
# SEVERITY DISTRIBUTION
# --------------------------------------------------
st.subheader("🔥 Severity Distribution")

if "severity" not in df.columns:
    df["severity"] = "Minimal"

sev_count = df["severity"].value_counts().reset_index()
sev_count.columns = ["Severity", "Count"]

pie = px.pie(
    sev_count,
    names="Severity",
    values="Count",
    color="Severity",
    color_discrete_map={
        "CRITICAL": "#d00000",
        "HIGH": "#f77f00",
        "MEDIUM": "#ffd166",
        "LOW": "#118ab2",
        "MINIMAL": "#06d6a0",
        "Critical": "#d00000",
        "High": "#f77f00",
        "Medium": "#ffd166",
        "Low": "#118ab2",
        "Minimal": "#06d6a0"
    }
)

st.plotly_chart(pie, use_container_width=True)
st.divider()

# --------------------------------------------------
# MITRE FREQUENCY
# --------------------------------------------------
st.subheader("🎯 MITRE Technique Frequency")

all_techniques = []
for event in data:
    all_techniques.extend(event.get("mitre_techniques", []))

if all_techniques:
    tech_df = pd.DataFrame(all_techniques, columns=["Technique"])
    count_df = tech_df.value_counts().reset_index(name="Count")

    mitre_chart = px.bar(
        count_df,
        x="Technique",
        y="Count",
        color="Count",
        color_continuous_scale="Turbo"
    )

    mitre_chart.update_layout(
        plot_bgcolor="#0f172a",
        paper_bgcolor="#0f172a",
        font_color="white"
    )

    st.plotly_chart(mitre_chart, use_container_width=True)
else:
    st.info("No MITRE techniques detected.")

st.divider()

# --------------------------------------------------
# CURRENT THREAT PANEL
# --------------------------------------------------
st.subheader("🧠 Current Threat Level")

if severity.upper() == "CRITICAL":
    st.error("🔴 CRITICAL SUPPLY CHAIN THREAT")
elif severity.upper() == "HIGH":
    st.error("🟠 HIGH RISK ACTIVITY")
elif severity.upper() == "MEDIUM":
    st.warning("🟡 MEDIUM RISK ACTIVITY")
elif severity.upper() == "LOW":
    st.info("🔵 LOW RISK ACTIVITY")
else:
    st.success("🟢 Minimal Threat Activity")

st.divider()

# --------------------------------------------------
# SHA256 DISPLAY
# --------------------------------------------------
st.subheader("🔐 Artifact SHA256 Hash")
st.code(latest_event.get("sha256", "Not available"))

st.divider()

# --------------------------------------------------
# FEATURE BREAKDOWN
# --------------------------------------------------
st.subheader("🧬 Behavioral Fingerprint Features")
st.json(latest_event.get("features", {}))

st.divider()

# --------------------------------------------------
# LATEST EVENTS TABLE
# --------------------------------------------------
st.subheader("📋 Event History")
st.dataframe(df.sort_values("timestamp", ascending=False))

st.divider()

# --------------------------------------------------
# DOWNLOAD REPORT
# --------------------------------------------------
st.subheader("⬇ Download Threat Report")

json_string = json.dumps(data, indent=4)
st.download_button(
    label="Download JSON Report",
    data=json_string,
    file_name="threat_report.json",
    mime="application/json"
)

st.markdown("---")
st.caption("AI-Driven Behavioral Supply Chain Security Monitoring System")