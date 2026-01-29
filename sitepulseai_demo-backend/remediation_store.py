# remediation_store.py
"""
remediation_store.py
-------------------
In-memory store for SitePulseAI pending remediations.
Safe, drop-in replacement to fix ImportError.
Compatible with autofix_engine, ssl_autofix, and frontend.
"""

from typing import List, Dict
from datetime import datetime

# -------------------------------
# Internal store
# -------------------------------
_pending_remediations: List[Dict] = []

# -------------------------------
# Add a new remediation task
# -------------------------------
def add_remediation(remediation: Dict):
    """
    Add a remediation task to the store.
    Args:
        remediation (dict): Must include at least 'site' and 'vuln_id'
    """
    remediation_copy = remediation.copy()
    remediation_copy["added_at"] = datetime.utcnow().isoformat()
    _pending_remediations.append(remediation_copy)

# -------------------------------
# Get all pending remediations
# -------------------------------
def get_pending_remediations() -> List[Dict]:
    """
    Return a copy of all pending remediation tasks.
    """
    return _pending_remediations.copy()

# -------------------------------
# Clear all pending remediations
# -------------------------------
def clear_remediations():
    """
    Empty the pending remediations store.
    """
    _pending_remediations.clear()

# -------------------------------
# Example helper: check pending count
# -------------------------------
def pending_count() -> int:
    """
    Return the number of pending remediation tasks.
    """
    return len(_pending_remediations)
