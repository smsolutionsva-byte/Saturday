import streamlit as st
import requests

# 1. Page Configuration (Must be the first Streamlit command)
st.set_page_config(
    page_title="SentinelAI Command Center", 
    page_icon="🛡️", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# Backend API URL
API_URL = "http://127.0.0.1:8000/api/v1/analyze"

# 2. Sidebar Configuration
with st.sidebar:
    st.image("https://img.icons8.com/color/96/000000/artificial-intelligence.png", width=60)
    st.title("System Status")
    st.success("🟢 Orchestrator: ONLINE")
    st.success("🟢 Cyber Agent: STANDBY")
    st.success("🟢 Finance Agent: STANDBY")
    st.success("🟢 Crisis Agent: STANDBY")
    st.divider()
    st.markdown("**SentinelAI Core Engine v1.0**")
    st.caption("Locally hosted agentic framework.")

# 3. Main Header
st.title("🛡️ SentinelAI Command Center")
st.markdown("Inject live threat payloads and watch the multi-agent system analyze and neutralize them in real-time.")
st.divider()

# 4. Input Section (Two Columns)
col1, col2 = st.columns([1, 2])

with col1:
    st.subheader("📡 Threat Ingestion")
    source_type = st.selectbox(
        "Select Threat Source Protocol:",
        ["Email", "SMS", "URL", "Invoice", "Transaction", "Weather_Alert", "SOS"]
    )
    urgency_level = st.select_slider(
        "Reported Urgency:",
        options=["low", "medium", "high", "critical"]
    )

with col2:
    st.subheader("📄 Payload Data")
    payload_text = st.text_area(
        "Paste the raw text, email body, or alert details here:",
        height=150,
        placeholder="e.g., URGENT: Your bank routing number has been updated. Click here..."
    )

# 5. Execution Button
if st.button("🚀 Scan Threat with SentinelAI", type="primary", use_container_width=True):
    if not payload_text:
        st.warning("Please enter a payload to scan.")
    else:
        # Show a loading spinner while waiting for FastAPI
        with st.spinner("Agents are analyzing the threat..."):
            
            # Prepare the data to send to your backend
            payload = {
                "source": source_type,
                "description": payload_text,
                "urgency": urgency_level
            }
            
            try:
                # Send POST request to FastAPI
                response = requests.post(API_URL, json=payload)
                
                if response.status_code == 200:
                    result = response.json()
                    orch_resp = result.get("orchestrator_response", {})
                    details = orch_resp.get("details", {})
                    
                    # 6. Display the Results in a clean UI
                    st.divider()
                    st.subheader("🧠 Multi-Agent Analysis Report")
                    
                    # Metrics row
                    r1, r2, r3 = st.columns(3)
                    r1.metric("Responding Agent", orch_resp.get("assigned_agent", "Unknown"))
                    r2.metric("Calculated Risk Score", details.get("calculated_risk_score", "N/A"))
                    
                    # Color code the severity
                    severity = details.get("threat_severity", "UNKNOWN")
                    if severity in ["CRITICAL", "HIGH RISK", "EMERGENCY (LEVEL 1)"]:
                        r3.error(f"Severity: {severity}")
                    elif severity in ["MEDIUM", "SUSPICIOUS", "WARNING (LEVEL 2)"]:
                        r3.warning(f"Severity: {severity}")
                    else:
                        r3.success(f"Severity: {severity}")
                    
                    # Details row
                    st.markdown("### 🔍 Anomalies Detected")
                    for anomaly in details.get("anomalies_found", []):
                        st.markdown(f"- 🚩 `{anomaly}`")
                        
                    st.markdown("### 🛡️ Recommended Action Playbook")
                    st.info(details.get("recommended_action", "No action specified."))
                    
                else:
                    st.error(f"Backend Error: {response.status_code}")
            
            except requests.exceptions.ConnectionError:
                st.error("🚨 Connection Failed! Is your FastAPI server running on port 8000?")