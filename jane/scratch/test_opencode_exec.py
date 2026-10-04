import urllib.request, json, time
from pathlib import Path

# Create session without directory query param
req1 = urllib.request.Request(
    'http://127.0.0.1:4096/session',
    data=json.dumps({'title': 'test_write'}).encode(),
    headers={'Content-Type': 'application/json'},
    method='POST'
)
with urllib.request.urlopen(req1) as resp:
    sid = json.loads(resp.read().decode())['id']

out_file = Path('data/investigations/test_fanout_muse/queries/fanout.json').resolve()
out_file.parent.mkdir(parents=True, exist_ok=True)
if out_file.exists():
    out_file.unlink()

prompt = f"Please write a file to {out_file.as_posix()} with valid JSON: {{\"success\": true, \"queries\": [\"guns darknet\"]}}"
p_payload = {
    'parts': [{'type': 'text', 'text': prompt}],
    'model': {'providerID': 'opencode', 'modelID': 'muse-spark-1.3-contributor-free'}
}
req2 = urllib.request.Request(
    f'http://127.0.0.1:4096/session/{sid}/prompt_async',
    data=json.dumps(p_payload).encode(),
    headers={'Content-Type': 'application/json'},
    method='POST'
)
with urllib.request.urlopen(req2) as resp:
    print('Dispatched:', resp.status)

t0 = time.time()
while time.time() - t0 < 35:
    if out_file.exists() and out_file.stat().st_size > 0:
        print('FILE WRITTEN!')
        print(out_file.read_text())
        break
    time.sleep(2)
else:
    print('Timed out, checking messages...')
    req3 = urllib.request.Request(f'http://127.0.0.1:4096/session/{sid}/message')
    with urllib.request.urlopen(req3) as resp:
        msgs = json.loads(resp.read().decode())
    for m in msgs:
        print(m.get('info', {}).get('role'), m.get('info', {}).get('error'))
        for p in m.get('parts', []):
            if p.get('type') in ('text', 'tool'):
                print(p)
