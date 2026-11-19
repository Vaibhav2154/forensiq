from services import ai_clients, ioc_extractor
import uuid
import os

KNOWLEDGE_BASE_ID = os.getenv("KNOWLEDGE_BASE_ID")

def run_analysis_pipeline(processed_log: dict):
    """
    Orchestrates the simplified, single-call analysis pipeline.
    """
    log_message = processed_log.get("message")
    if not log_message:
        return {"error": "Processed log is missing a 'message' field."}

    # --- SINGLE AI STEP: Call Bedrock for mapping and summarization ---
    analysis_result = ai_clients.get_bedrock_analysis(log_message, KNOWLEDGE_BASE_ID)
    
    if not analysis_result:
        return {"error": "Failed to get analysis from Bedrock."}

    # --- Assemble the Final Report ---
    iocs = ioc_extractor.extract_iocs_from_log(log_message)
    
    technique_id = "N/A"
    if analysis_result.get("mapped_sources"):
        technique_id = analysis_result["mapped_sources"][0].replace('.txt', '').replace('_', '.')

    final_report_item = {
        "log_id": processed_log.get("log_id", str(uuid.uuid4())),
        "timestamp": processed_log.get("timestamp"),
        "raw_log": log_message,
        "ai_summary": analysis_result["ai_summary"],
        "mitre_mapping": {
            "technique_id": technique_id,
        },
        "iocs": iocs
    }
    
    return final_report_item