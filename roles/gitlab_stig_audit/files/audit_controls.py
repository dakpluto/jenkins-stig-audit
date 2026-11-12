"""Read-only target collector. Emit identifiers only, never free-form event details."""
import json
import sys

out = {"samples": "", "external": {}, "errors": []}
try:
    with open(sys.argv[1], "rb") as stream:
        stream.seek(0, 2)
        size = stream.tell()
        stream.seek(max(0, size - 262144))
        if size > 262144:
            stream.readline()
        lines = stream.read(262144).decode("utf-8", "replace").splitlines()[-200:]
    rows = []
    for line in lines:
        try:
            row = json.loads(line)
            details = row.get("details") or {}
            rows.append({key: row[key] for key in
                         ("author_id", "user_id", "created_at", "time", "target_id", "event_type") if key in row})
            rows[-1]["event_type"] = row.get("event_type") or details.get("event_type")
        except (ValueError, TypeError, AttributeError):
            continue
    out["samples"] = "\n".join(json.dumps(row) for row in rows)
except OSError as exc:
    out["errors"].append("audit sample: " + str(exc))
if sys.argv[2]:
    try:
        with open(sys.argv[2], "rb") as stream:
            payload = stream.read(1048577)
        if len(payload) > 1048576:
            raise ValueError("external evidence exceeds 1 MiB")
        doc = json.loads(payload.decode("utf-8"))
        if not isinstance(doc, dict):
            raise ValueError("external evidence must be an object")
        out["external"] = doc
    except (OSError, ValueError) as exc:
        out["errors"].append("external evidence: " + str(exc))
print(json.dumps(out))
