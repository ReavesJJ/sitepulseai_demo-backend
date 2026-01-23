# ssl_state.py
from datetime import datetime
from typing import Dict, Optional

# -----------------------------
# In-memory SSL state store
# -----------------------------
_ssl_store: Dict[str, Dict] = {}

# -----------------------------
# Functions
# -----------------------------
def get_ssl_state(domain: str) -> Dict:
    """
    Returns current SSL state for a domain.
    """
    domain_data = _ssl_store.get(domain, {})
    return {
        "domain": domain,
        "ssl_status": domain_data.get("ssl_status", "unknown"),
        "last_checked_at": domain_data.get("last_checked_at"),
        "expiry_date": domain_data.get("expiry_date"),
        "renewal_mode": domain_data.get("renewal_mode", "monitor_only"),
        "assisted_renewed_at": domain_data.get("assisted_renewed_at"),
    }

def update_ssl_observation(domain: str, ssl_status: str, expiry_date: Optional[str] = None):
    """
    Updates SSL observation for a domain.
    """
    now = datetime.utcnow().isoformat()
    domain_data = _ssl_store.get(domain, {})
    domain_data.update({
        "ssl_status": ssl_status,
        "last_checked_at": now,
        "expiry_date": expiry_date or domain_data.get("expiry_date"),
    })
    _ssl_store[domain] = domain_data
    return domain_data

def set_renewal_mode(domain: str, mode: str):
    """
    Sets the SSL renewal mode: 'monitor_only' or 'assisted'.
    """
    domain_data = _ssl_store.get(domain, {})
    domain_data["renewal_mode"] = mode
    _ssl_store[domain] = domain_data
    return {"domain": domain, "renewal_mode": mode}

def mark_assisted_renewal(domain: str):
    """
    Marks that assisted SSL renewal has been approved/executed.
    """
    now = datetime.utcnow().isoformat()
    domain_data = _ssl_store.get(domain, {})
    domain_data["assisted_renewed_at"] = now
    _ssl_store[domain] = domain_data
    return {"domain": domain, "assisted_renewed_at": now}
