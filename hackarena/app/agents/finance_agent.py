import os
from pydantic import BaseModel, Field
from langchain_groq import ChatGroq
from langchain_core.prompts import PromptTemplate

class FinanceAnalysisResult(BaseModel):
    agent_name: str = Field(default="Financial Compliance Guard")
    calculated_risk_score: str = Field(description="A percentage score ending in %, e.g., '92%' or '0%'")
    threat_severity: str = Field(description="Must be exactly one of: APPROVED, SUSPICIOUS, HIGH RISK")
    anomalies_found: list[str] = Field(description="List of specific compliance violations or pressure tactics found.")
    recommended_action: str = Field(description="A clear, actionable financial control step.")

def analyze_financial_threat(description: str) -> dict:
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return {
            "agent_name": "Financial Compliance Guard",
            "calculated_risk_score": "ERROR",
            "threat_severity": "UNKNOWN",
            "anomalies_found": ["Groq API key is missing from the .env file."],
            "recommended_action": "Add your GROQ_API_KEY to proceed."
        }

    try:
        # Switch LLM to Groq Llama 3
        llm = ChatGroq(model="llama-3.3-70b-versatile", temperature=0, groq_api_key=api_key)
        structured_llm = llm.with_structured_output(FinanceAnalysisResult)
        
        prompt_template = PromptTemplate.from_template(
            """You are the Financial Compliance Guard for SentinelAI.
            Audit the following financial communication or invoice for wire fraud, 
            invoice hijacking, or Business Email Compromise (BEC).
            
            Payload to analyze:
            "{payload}"
            """
        )
        
        formatted_prompt = prompt_template.format(payload=description)
        result = structured_llm.invoke(formatted_prompt)
        return result.dict()
    except Exception as e:
        return {
            "agent_name": "Financial Compliance Guard",
            "calculated_risk_score": "ERROR",
            "threat_severity": "HIGH RISK",
            "anomalies_found": [f"Groq API Error: {str(e)}"],
            "recommended_action": "Check Groq console status."
        }