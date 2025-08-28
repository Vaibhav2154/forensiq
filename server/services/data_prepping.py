import re
import uuid
from datetime import datetime

LOG_PATTERN = re.compile(r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<process_name>\w+).*?:\s+(?P<message>.*)')

def normalize_timestamp(ts_str: str) -> str:
    try:
        dt_obj = datetime.strptime(f"{datetime.now().year} {ts_str}", '%Y %b %d %H:%M:%S')
        return dt_obj.isoformat() + "Z"
    except ValueError:
        return datetime.now().isoformat() + "Z"

def clean_text(text: str) -> str:
    text = text.lower()
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def process_logs(raw_logs: list[str]) -> list[dict]:
    structured_logs = []
    for log_line in raw_logs:
        if not log_line.strip():
            continue

        match = LOG_PATTERN.match(log_line.strip())
        if match:
            log_data = match.groupdict()
            raw_message = log_data.get("message", "").strip()
            structured_logs.append({
                "log_id": str(uuid.uuid4()),
                "timestamp": normalize_timestamp(log_data.get("timestamp")),
                "hostname": log_data.get("hostname"),
                "process_name": log_data.get("process_name"),
                "raw_message": raw_message,
                "cleaned_message_for_ai": clean_text(raw_message)
            })
        else:
            raw_message = log_line.strip()
            structured_logs.append({
                "log_id": str(uuid.uuid4()),
                "timestamp": datetime.now().isoformat() + "Z",
                "raw_message": raw_message,
                "cleaned_message_for_ai": clean_text(raw_message),
            })
    return structured_logs