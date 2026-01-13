import json
from datetime import datetime

STATE_FILE = "ssl_state.json"

def load_ssl_state():
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except:
        return {}

def save_ssl_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

def update_ssl_state(domain, renewed=False, mode="assisted"):
    state = load_ssl_state()
    state[domain] = {
        "last_renewed_by": "SitePulseAI" if renewed else None,
        "last_checked": datetime.utcnow().isoformat(),
        "renewal_mode": mode,
    }
    save_ssl_state(state)
