# In app/core/orchestrator.py

from services import aiclient, ioc_extractor
import os

KNOWLEDGE_BASE_ID = os.getenv("KNOWLEDGE_BASE_ID")

def run_analysis_pipeline(processed_log: dict):
    # Use the cleaned message for better AI performance
    cleaned_message = processed_log.get("cleaned_message_for_ai")
    if not cleaned_message:
        return {"error": "Processed log is missing a message field."}

    analysis_result = aiclient.get_bedrock_analysis(cleaned_message, KNOWLEDGE_BASE_ID)
    
    if not analysis_result:
        return {"error": "Failed to get analysis from Bedrock."}

    # Use the original raw message for IOC extraction to not miss any data
    iocs = ioc_extractor.extract_iocs(processed_log.get("raw_message", ""))
    
    technique_id = "N/A"
    if analysis_result.get("mapped_sources"):
        technique_id = analysis_result["mapped_sources"][0].replace('.txt', '').replace('_', '.')

    return {
        "log_id": processed_log.get("log_id"),
        "timestamp": processed_log.get("timestamp"),
        "raw_log": processed_log.get("raw_message"),
        "ai_summary": analysis_result["ai_summary"],
        "mitre_mapping": {
            "technique_id": technique_id,
            "details": analysis_result["ai_summary"] 
        },
        "iocs": iocs
    }