
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
scm-history-item:c%3A%5CProjects%5Cforensiq?%7B%22repositoryId%22%3A%22scm0%22%2C%22historyItemId%22%3A%22dbd5009a2366601ef857ec2e2dd82b4a03c48903%22%2C%22historyItemParentId%22%3A%2242da03f68724325a62a164fba3c7f4c4ff54f9cd%22%2C%22historyItemDisplayId%22%3A%22dbd5009%22%7D                found_iocs.append({"type": ioc_type, "value": match})
                seen_iocs.add(match)
    return found_iocs