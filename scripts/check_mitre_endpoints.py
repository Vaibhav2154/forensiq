import urllib.request
import json

endpoints = [
    'http://127.0.0.1:8000/api/mitre/tactics',
    'http://127.0.0.1:8000/api/mitre/platforms'
]

for url in endpoints:
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            status = resp.status
            body = resp.read().decode('utf-8')
            try:
                parsed = json.loads(body)
                pretty = json.dumps(parsed, indent=2)
            except Exception:
                pretty = body
            print(f"URL: {url}\nStatus: {status}\nBody:\n{pretty}\n---\n")
    except Exception as e:
        print(f"URL: {url}\nError: {e}\n---\n")
