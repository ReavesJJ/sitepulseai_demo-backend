# ============================================================
# SitePulseAI Telemetry Event Store
# Shared Telemetry Evidence Layer
# ============================================================

import os
import json
import hashlib
from datetime import datetime


# ============================================================
# Telemetry Storage
# ============================================================

TELEMETRY_DIR = "telemetry_events"
TELEMETRY_FILE = os.path.join(
    TELEMETRY_DIR,
    "telemetry_event_log.json"
)

os.makedirs(TELEMETRY_DIR, exist_ok=True)


# ============================================================
# Domain Normalization
# ============================================================

def normalize_domain(domain: str) -> str:
    """
    Normalize a domain for telemetry-chain matching.

    Examples:
        sitepulseai.com
        www.sitepulseai.com
        https://sitepulseai.com

    all resolve to:
        sitepulseai.com
    """

    normalized = str(domain).strip().lower()

    if normalized.startswith("https://"):
        normalized = normalized[8:]
    elif normalized.startswith("http://"):
        normalized = normalized[7:]

    normalized = normalized.replace("www.", "", 1)

    # Remove path if one was supplied accidentally.
    normalized = normalized.split("/")[0]

    return normalized


# ============================================================
# Load Existing Telemetry Events
# ============================================================

def load_telemetry_events() -> list:
    """
    Load the current telemetry event history.

    Returns an empty list when no telemetry file exists yet.
    """

    if not os.path.exists(TELEMETRY_FILE):
        return []

    try:
        with open(
            TELEMETRY_FILE,
            "r",
            encoding="utf-8"
        ) as f:
            telemetry_events = json.load(f)

    except (OSError, json.JSONDecodeError) as e:
        raise RuntimeError(
            f"Unable to read telemetry events: {e}"
        )

    if not isinstance(telemetry_events, list):
        return []

    return telemetry_events


# ============================================================
# Find Previous Hash for Client + Domain
# ============================================================

def find_previous_event_hash(
    telemetry_events: list,
    client_id: str,
    domain: str
) -> str:
    """
    Return the most recent event hash belonging to the same
    licensed client and domain.

    Each client/domain therefore maintains its own telemetry
    hash chain.

    First event:
        GENESIS

    Later events:
        GENESIS -> HASH1 -> HASH2 -> HASH3
    """

    requested_domain = normalize_domain(domain)

    for event in reversed(telemetry_events):

        event_client = event.get("client_id")

        event_domain = normalize_domain(
            event.get("domain", "")
        )

        if (
            event_client == client_id
            and event_domain == requested_domain
        ):
            return event.get(
                "event_hash",
                "GENESIS"
            )

    return "GENESIS"


# ============================================================
# Create Telemetry Event
# ============================================================

def create_telemetry_event(
    client_id: str,
    domain: str,
    results: dict
) -> dict:
    """
    Create and persist a SitePulseAI monitoring telemetry event.

    This function is shared by:

        1. Manual /monitor execution
        2. Autonomous monitoring

    It does NOT generate a telemetry certificate.
    Certificate generation remains a separate operation.
    """

    if not client_id:
        raise ValueError(
            "client_id is required for telemetry event creation."
        )

    if not domain:
        raise ValueError(
            "domain is required for telemetry event creation."
        )

    if not isinstance(results, dict):
        raise ValueError(
            "results must be a dictionary."
        )

    # --------------------------------------------------------
    # 1. Load existing telemetry history
    # --------------------------------------------------------

    telemetry_events = load_telemetry_events()

    # --------------------------------------------------------
    # 2. Determine previous event hash
    #
    # IMPORTANT:
    # Chain is specific to this client + domain.
    # --------------------------------------------------------

    previous_hash = find_previous_event_hash(
        telemetry_events,
        client_id,
        domain
    )

    # --------------------------------------------------------
    # 3. Build event
    # --------------------------------------------------------

    event_record = {
        "event_type": "monitoring_event",
        "event_id": (
            f"SP-{os.urandom(4).hex().upper()}"
        ),
        "timestamp": datetime.utcnow().isoformat(),
        "client_id": client_id,
        "domain": domain,
        "monitoring_agent":
            "SitePulseAI Monitoring Engine",
        "previous_event_hash": previous_hash,
        "results_snapshot": results
    }

    # --------------------------------------------------------
    # 4. Generate deterministic SHA-256 event hash
    # --------------------------------------------------------

    event_string = json.dumps(
        event_record,
        sort_keys=True,
        default=str
    )

    event_hash = hashlib.sha256(
        event_string.encode()
    ).hexdigest()

    event_record["event_hash"] = event_hash

    # --------------------------------------------------------
    # 5. Persist event
    # --------------------------------------------------------

    telemetry_events.append(event_record)

    try:
        with open(
            TELEMETRY_FILE,
            "w",
            encoding="utf-8"
        ) as f:
            json.dump(
                telemetry_events,
                f,
                indent=2,
                default=str
            )

    except OSError as e:
        raise RuntimeError(
            f"Unable to write telemetry event: {e}"
        )

    # --------------------------------------------------------
    # 6. Return event
    # --------------------------------------------------------

    return event_record