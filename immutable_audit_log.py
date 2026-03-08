import os
import json
from datetime import datetime
import gzip
import shutil

AUDIT_LOG_FOLDER = "audit_logs"
MAX_LOG_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB per log file

def _get_log_file_path():
    os.makedirs(AUDIT_LOG_FOLDER, exist_ok=True)
    path = os.path.join(AUDIT_LOG_FOLDER, "events.log")
    return path

def _rotate_log_if_needed():
    path = _get_log_file_path()
    if not os.path.exists(path):
        return
    if os.path.getsize(path) >= MAX_LOG_SIZE_BYTES:
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        compressed_path = os.path.join(AUDIT_LOG_FOLDER, f"events_{timestamp}.log.gz")
        with open(path, "rb") as f_in, gzip.open(compressed_path, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
        # Clear the current log
        open(path, "w").close()

def write_audit_log(event_data: dict):
    """
    Append an immutable audit event
    """
    event_data["timestamp"] = datetime.utcnow().isoformat()
    _rotate_log_if_needed()
    path = _get_log_file_path()
    with open(path, "a") as f:
        f.write(json.dumps(event_data, sort_keys=True) + "\n")