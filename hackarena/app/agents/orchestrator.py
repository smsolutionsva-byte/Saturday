import json
import os
from app.agents.cyber_agent import analyze_cyber_threat
from app.agents.finance_agent import analyze_financial_threat
from app.agents.crisis_agent import analyze_crisis_threat

def route_incident(payload: dict) -> dict:
    """
    Processes payloads. Instantly returns a 100% match if a URL is found 
    inside the blocklist.json file; otherwise, delegates to the AI agents.
    """
    description = payload.get("description", "")
    
    # 1. CHECK THE BLOCKLIST JSON FIRST
    blocklist_path = "blocklist.json"
    if os.path.exists(blocklist_path):
        try:
            with open(blocklist_path, "r") as f:
                data = json.load(f)
                known_fake_urls = data.get("fake_urls", [])
                
                # Check if any known fake URL is mentioned inside the description text
                for fake_url in known_fake_urls:
                    if fake_url in description:
                        print(f"[SENTINEL CORE] BLOCKLIST MATCH DETECTED: {fake_url}")
                        return {
                            "orchestrator_response": {
                                "assigned_agent": "Sentinel Blocklist Guard",
                                "details": {
                                    "calculated_risk_score": "100%",
                                    "threat_severity": "CRITICAL",
                                    "anomalies_found": [
                                        "Matches an exact signature in the local malicious threat database.",
                                        f"Flagged URL: {fake_url}"
                                    ],
                                    "recommended_action": "BLOCK IMMEDIATELY. This link is confirmed to be a malicious phishing attempt."
                                }
                            }
                        }
        except Exception as e:
            print(f"[SENTINEL CORE] Error reading blocklist: {e}")

    # 2. IF NOT IN BLOCKLIST, RUN REGULAR AGENTS (Your existing code)
    raw_source = payload.get("source") or payload.get("threat_type") or "unknown"
    source_clean = str(raw_source).lower()

    if any(keyword in source_clean for keyword in ["email", "link", "url", "phish"]):
        ai_response = analyze_cyber_threat(description)
    elif any(keyword in source_clean for keyword in ["invoice", "finance", "billing", "transaction"]):
        ai_response = analyze_financial_threat(description)
    elif any(keyword in source_clean for keyword in ["weather", "crisis", "sos", "alert"]):
        ai_response = analyze_crisis_threat(description)
    else:
        ai_response = analyze_cyber_threat(description)

    if not isinstance(ai_response, dict):
        ai_response = {}

    agent = ai_response.get("agent_name") or ai_response.get("agent") or "Cyber-Safety Guard"
    risk = ai_response.get("calculated_risk_score") or ai_response.get("risk_score") or "80%"
    severity = ai_response.get("threat_severity") or ai_response.get("severity") or "MEDIUM"
    anomalies = ai_response.get("anomalies_found") or ai_response.get("anomalies") or ["Suspicious payload behavior detected"]
    action = ai_response.get("recommended_action") or ai_response.get("recommendation") or "Isolate the endpoint."

    return {
        "orchestrator_response": {
            "assigned_agent": agent,
            "details": {
                "calculated_risk_score": risk,
                "threat_severity": str(severity).upper(),
                "anomalies_found": anomalies,
                "recommended_action": action
            }
        }
    }