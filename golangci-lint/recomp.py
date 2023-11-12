import json

data = {}
with open('report-unformatted.json', 'r') as f_read:
    data = json.loads(f_read.read())
with open('report.json', 'w') as f_write:
    f_write.write(json.dumps(data.get("Issues", []), indent=4))
