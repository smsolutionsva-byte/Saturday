import time
import random
import requests

# The URL where your FastAPI server is listening
TARGET_URL = "http://127.0.0.1:8000/api/v1/analyze"

# A collection of simulated real-world threats
THREAT_POOL = [
    {
        "source": "email",
        "description": "URGENT: Abnormal login attempt detected from Russia. Click http://bit.ly/secure-login-302 to verify your security details immediately.",
        "urgency": "high"
    },
    {
        "source": "sms",
        "description": "Dear user, your bank package delivery failed. Please update your banking details at http://unsecure-delivery.info to claim it.",
        "urgency": "medium"
    },
    {
        "source": "email",
        "description": "Hey team, just checking in to see if the quarterly presentation slides are ready for tomorrow's review. Thanks!",
        "urgency": "low"
    },
    {
        "source": "invoice",
        "description": "PENDING INVOICE #9482. Total Amount Due: $14,250.00. Payment routing details have been updated. Process within 24 hours.",
        "urgency": "high"
    },
    {
        "source": "weather_alert",
        "description": "CRITICAL: Flash flood warning issued for Bengaluru local areas. High risk of structural flooding and power outages. Seek high ground.",
        "urgency": "critical"
    }
]

def stream_threats():
    print("🚀 SentinelAI Threat Stream Simulator Started...")
    print(f"📡 Target Endpoint: {TARGET_URL}")
    print("--------------------------------------------------")
    
    while True:
        # 1. Pick a random threat from our pool
        threat = random.choice(THREAT_POOL)
        print(f"\n[+] Ingesting new raw event source: {threat['source'].upper()}")
        print(f"[*] Payload Text: '{threat['description']}'")
        
        try:
            # 2. Fire the threat at our FastAPI backend
            response = requests.post(TARGET_URL, json=threat)
            
            if response.status_code == 200:
                result = response.json()
                orchestrator_res = result.get("orchestrator_response", {})
                assigned_agent = orchestrator_res.get("assigned_agent", "Unknown")
                
                print(f"✔️ Successfully processed by Backend!")
                print(f"🤖 Routed to Agent: {assigned_agent}")
                
                # If it went to the Cyber Agent, print out its detailed calculations
                if "details" in orchestrator_res:
                    details = orchestrator_res["details"]
                    print(f"📊 Calculated Risk: {details.get('calculated_risk_score')}")
                    print(f"⚠️ Severity Level: {details.get('threat_severity')}")
                    print(f"🔍 Anomalies Found: {details.get('anomalies_found')}")
            else:
                print(f"❌ Server returned error code: {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            print("❌ Connection Error: Is your FastAPI server running on http://127.0.0.1:8000? Run 'python -m uvicorn app.main:app --reload' in your other terminal.")

        # 3. Wait 8 seconds before sending the next threat string
        time.sleep(8)

if __name__ == "__main__":
    stream_threats()