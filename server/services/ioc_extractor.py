
import re

IOC_PATTERNS = {
    'ipv4': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}\b',
    'url': r'https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)',
    'md5': r'\b[a-fA-F0-9]{32}\b',
    'sha256': r'\b[a-fA-F0-9]{64}\b',
}

def extract_iocs(log_message: str) -> list[dict]:
    found_iocs = []
    seen_iocs = set()
    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = re.findall(pattern, log_message)
        for match in matches:
            if match not in seen_iocs:
                found_iocs.append({"type": ioc_type, "value": match})
                seen_iocs.add(match)
    return found_iocs