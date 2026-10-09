import json
from dataclasses import replace
from test_broker import call, approve


def test_optional_audit_records_metadata_not_commands(running):
    b,pw = running
    b.config = replace(b.config,audit_enabled=True)
    r = call(b,'agent','request',mode='full',duration=900,reason='a sensitive reason that must not be logged')
    approve(b,pw,r['id'])
    call(b,'agent','execute',command='printf private-command-content')
    call(b,'agent','revoke',id=r['id'])
    path = b.leases.path.parent/'audit.jsonl'
    text = path.read_text()
    assert 'private-command-content' not in text and r['reason'] not in text and pw not in text
    rows = [json.loads(line) for line in text.splitlines()]
    assert any(row['event'] == 'execution-finished' and row['exitcode'] == 0 for row in rows)
    assert path.stat().st_mode & 0o777 == 0o600
