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
st.set_page_config(page_title="AI DevSecOps SOC", layout="wide")

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

st.title("🛡 Real-Time DevSecOps Threat Intelligence Center")

# --------------------------------------------------
# LOAD DATA
# --------------------------------------------------
if not os.path.exists("security_report.json"):
    st.warning("Run realtime_engine.py first.")
    st.stop()

with open("security_report.json", "r") as f:
    data = json.load(f)

if not isinstance(data, list):
    data = [data]

df = pd.DataFrame(data)
df["timestamp"] = pd.to_datetime(df["timestamp"])

latest_event = df.iloc[-1]

risk_score = latest_event["risk_score"]
anomaly_score = latest_event["anomaly_score"]
mitre_count = len(latest_event["mitre_techniques"])

# --------------------------------------------------
# SEVERITY CLASSIFICATION
# --------------------------------------------------
def classify(score):
    if score >= 85:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 40:
        return "Medium"
    elif score >= 20:
        return "Low"
    else:
        return "Minimal"

df["severity"] = df["risk_score"].apply(classify)
current_severity = classify(risk_score)

# --------------------------------------------------
# KPI SECTION
# --------------------------------------------------
col1, col2, col3 = st.columns(3)
col1.metric("⚠ Risk Score", risk_score)
col2.metric("📡 Anomaly Score", anomaly_score)
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

sev_count = df["severity"].value_counts().reset_index()
sev_count.columns = ["Severity", "Count"]

pie = px.pie(
    sev_count,
    names="Severity",
    values="Count",
    color="Severity",
    color_discrete_map={
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

st.divider()

# --------------------------------------------------
# CURRENT THREAT PANEL
# --------------------------------------------------
st.subheader("🧠 Current Threat Level")

if current_severity == "Critical":
    st.error("🔴 CRITICAL THREAT DETECTED")
elif current_severity == "High":
    st.error("🟠 HIGH RISK ACTIVITY")
elif current_severity == "Medium":
    st.warning("🟡 MEDIUM RISK ACTIVITY")
elif current_severity == "Low":
    st.info("🔵 LOW RISK ACTIVITY")
else:
    st.success("🟢 Minimal Threat Activity")

st.divider()

# --------------------------------------------------
# LATEST 5 EVENTS
# --------------------------------------------------
st.subheader("⏱ Latest 5 Events")

latest5 = df.sort_values("timestamp", ascending=False).head(5)
st.dataframe(latest5)

st.divider()

# --------------------------------------------------
# FULL EVENT TABLE
# --------------------------------------------------
st.subheader("📋 Full Event History")
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
st.caption("Adaptive AI-Driven Real-Time Threat Monitoring System")