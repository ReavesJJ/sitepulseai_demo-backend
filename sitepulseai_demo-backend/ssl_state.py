# ssl_state.py
# In-memory SSL state registry
ssl_registry = {}

def update_ssl_state(domain: str, state: str):
    ssl_registry[domain] = state

def get_ssl_status(domain: str) -> str:
    return ssl_registry.get(domain, "UNKNOWN")
