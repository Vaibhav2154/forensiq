import re
import uuid
import json
from string import punctuation

# This is a simplified regex from our previous discussion
LOG_PATTERN = re.compile(r'^(?P<timestamp>.*?)\s+(?P<hostname>\S+)\s+(?P<process_name>\w+).*?:\s+(?P<message>.*)')

def clean_text(text: str) -> str:
    """
    A simple text cleaning function using standard Python libraries.
    - Converts text to lowercase.
    - Removes specific punctuation.
    - Normalizes whitespace.
    """
    # Convert to lowercase
    text = text.lower()
    
    # Define punctuation to remove, but keep characters that might be important in logs
    custom_punctuation = punctuation.replace("-", "").replace("_", "").replace(":", "")
    text = text.translate(str.maketrans('', '', custom_punctuation))
    
    # Remove extra whitespace and strip leading/trailing spaces
    text = re.sub(r'\s+', ' ', text).strip()
    
    return text

def process_logs(raw_logs: list[str]) -> list[dict]:
    structured_logs = []
    for log_line in raw_logs:
        match = LOG_PATTERN.match(log_line.strip())
        if match:
            log_data = match.groupdict()
            
            # Apply the cleaning function to the messy log message
            raw_message = log_data.get("message", "").strip()
            cleaned_message = clean_text(raw_message)

            structured_log = {
                "log_id": str(uuid.uuid4()),
                "timestamp": log_data.get("timestamp"),
                "hostname": log_data.get("hostname"),
                "process_name": log_data.get("process_name"),
                "raw_message": raw_message,
                "cleaned_message_for_ai": cleaned_message # <-- This goes to the AI
            }
            structured_logs.append(structured_log)
        else:
            # Handle logs that don't match the regex pattern
            raw_message = log_line.strip()
            structured_logs.append({
                "log_id": str(uuid.uuid4()),
                "raw_message": raw_message,
                "cleaned_message_for_ai": clean_text(raw_message),
                "parsing_status": "unstructured"
            })
            
    return structured_logs

