def analyze_crisis_threat(description: str) -> dict:
    """
    Evaluates physical world telemetry (weather alerts, structural fires, 
    power outages) to trigger local safety playbooks.
    """
    text = description.lower()
    risk_score = 0
    impacted_assets = []
    
    # 1. Detect Alert Severity Levels
    if any(word in text for word in ["critical", "sos", "extreme", "evacuate"]):
        risk_score += 50
    elif any(word in text for word in ["warning", "alert", "moderate"]):
        risk_score += 25

    # 2. Categorize the physical event type
    if any(word in text for word in ["flood", "rain", "water", "storm"]):
        risk_score += 30
        impacted_assets.append("Environmental: High risk of ground-floor server room flooding.")
    elif any(word in text for word in ["fire", "smoke", "combustion"]):
        risk_score += 40
        impacted_assets.append("Life Safety: Atmospheric hazards detected. HVAC shutdown required.")
    elif any(word in text for word in ["power", "outage", "offline", "grid"]):
        risk_score += 20
        impacted_assets.append("IT Infrastructure: Grid failure risk. Local UPS systems on standby.")

    # 3. Geofence Matching (Simulating a match with your local office)
    location_keywords = ["bengaluru", "local areas", "electronic city", "headquarters"]
    found_locations = [loc for loc in location_keywords if loc in text]
    if found_locations:
        risk_score += 20
        impacted_assets.append(f"Geofence Alert: Alert perimeter overlaps with corporate assets near {found_locations}")

    # Cap risk score at 100
    risk_score = min(risk_score, 100)
    
    # Calculate Remediation Playbooks
    if risk_score >= 80:
        severity = "EMERGENCY (LEVEL 1)"
        remedy = "INITIATE PLAYBOOK ALPHA: Broadcast SMS evacuation to regional staff. Trigger automated cloud failover."
    elif risk_score >= 40:
        severity = "WARNING (LEVEL 2)"
        remedy = "STANDBY MODE: Alert facility management. Switch local servers to battery backup."
    else:
        severity = "ADVISORY (LEVEL 3)"
        remedy = "Continue routine monitoring."
        
    return {
        "agent_name": "Physical Crisis Guard",
        "calculated_risk_score": f"{risk_score}%",
        "threat_severity": severity,
        "anomalies_found": impacted_assets if impacted_assets else ["No immediate corporate assets in blast radius."],
        "recommended_action": remedy
    }