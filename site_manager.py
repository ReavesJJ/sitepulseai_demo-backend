import json

def get_all_sites():
    with open("license/license.json") as f:
        data = json.load(f)
    return data.get("domains", [])