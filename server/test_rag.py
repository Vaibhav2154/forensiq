import requests
import json

try:
    response = requests.post(
        'http://localhost:8000/api/mitre/rag-query',
        json={
            'query': 'What are common phishing techniques?',
            'max_context_techniques': 3,
            'include_source_techniques': True
        },
        timeout=30
    )
    print(f'Status: {response.status_code}')
    if response.status_code == 200:
        print('Success! RAG endpoint is working')
        data = response.json()
        print(f'Response keys: {list(data.keys())}')
        print(f'Response length: {len(data.get("response", ""))} characters')
    else:
        print(f'Error response: {response.text}')
except Exception as e:
    print(f'Error: {e}')