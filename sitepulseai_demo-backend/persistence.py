import json
import os

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

def save_baseline(domain: str, baseline: dict):
    path = os.path.join(DATA_DIR, f"{domain}.json")
    with open(path, "w") as f:
        json.dump(baseline, f, indent=2)

def load_baseline(domain: str):
    path = os.path.join(DATA_DIR, f"{domain}.json")
    if not os.path.exists(path):
        return None

    with open(path) as f:
        return json.load(f)
