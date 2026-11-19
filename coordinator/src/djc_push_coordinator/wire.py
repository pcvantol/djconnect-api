"""Passive r3 DATA decoders. Parsing is never signature/admission verification."""
import base64
import json
import re

MAX = 9_007_199_254_740_991
ROLES = ("widget_transport", "status_activity_transport")
ROLE_PATHS = tuple("/api/djconnect/v1/surface_registration/" + role + "/state" for role in ROLES)
COORD = ("pairing_epoch", "push_authority_id", "push_authority_revision", "original_operation_id",
         "parent_enrollment_id", "parent_enrollment_generation", "A_body_sha256")
DESCRIPTOR = ("core_instance_id", "installation_id", "entry_id", "device_id", "client_id", "client_type",
              "auth_generation", "pairing_digest_sha256") + COORD + (
              "device_platform", "application_id", "transport_role", "policy_id", "policy_revision",
              "policy_sha256", "clock_witness_sha256", "issued_at_unix_ms", "operation_deadline_unix_ms",
              "device_enrollment_expires_at_unix_ms")
CHILD = ("version", "state") + COORD + ("child_id", "child_revision", "B_body_sha256", "outcome")
OUTCOMES = ("CURRENT", "RETIRED", "EXPIRED", "UNKNOWN", "COMMITTED_BUT_SUPPRESSED")
# Types are contract-owned, never inferred from an identifier's suffix.
# In particular auth_generation is an opaque credential-generation string.
INTEGER_FIELDS = frozenset({"push_authority_revision", "parent_enrollment_generation",
                            "policy_revision", "issued_at_unix_ms", "operation_deadline_unix_ms",
                            "device_enrollment_expires_at_unix_ms", "child_revision"})


class InvalidWire(ValueError):
    pass


def _fail(*_):
    raise InvalidWire("invalid DATA wire")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail()
        result[key] = value
    return result


def decode(raw: bytes, limit: int):
    if type(raw) is not bytes or type(limit) is not int or not 0 < len(raw) <= limit:
        _fail()
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs,
                           parse_float=_fail, parse_constant=_fail)
        if json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii") != raw:
            _fail()
        return value
    except (ValueError, UnicodeError, RecursionError) as error:
        raise InvalidWire("invalid canonical DATA") from error


def _keys(value, keys):
    if type(value) is not dict or tuple(value) != tuple(keys):
        _fail()


def _fields(value):
    for name, v in value.items():
        if name == "version":
            if type(v) is not int or v != 1:
                _fail()
        elif name == "state":
            if type(v) is not str:
                _fail()
        elif name in INTEGER_FIELDS:
            if type(v) is not int or not 1 <= v <= MAX:
                _fail()
        elif name.endswith("sha256"):
            if type(v) is not str or re.fullmatch(r"[a-f0-9]{64}", v) is None:
                _fail()
        elif name in ("original_operation_id", "parent_enrollment_id", "child_id"):
            if type(v) is not str or re.fullmatch(r"[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}", v) is None:
                _fail()
        elif type(v) is not str or re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", v) is None:
            _fail()


def role_state(raw: bytes, exact_path: str):
    if exact_path not in ROLE_PATHS:
        _fail()
    v = decode(raw, 16384)
    if type(v) is not dict:
        _fail()
    state = v.get("state")
    if state in ("WAITING_AUTHORITY", "UNAVAILABLE"):
        _keys(v, ("version", "state"))
    elif state in ("RETIRED", "UNKNOWN"):
        _keys(v, ("version", "state") + COORD)
    elif state == "AUTHORITY_CURRENT":
        _keys(v, ("version", "state") + DESCRIPTOR)
    else:
        _fail()
    _fields(v)  # Validate primitive types before hashing/lookup/comparison.
    if state == "AUTHORITY_CURRENT":
        role = ROLES[ROLE_PATHS.index(exact_path)]
        mapping = {"ios": "ios", "ipados": "ios", "macos": "macos", "watchos": "watchos"}
        if (v["transport_role"] != role or v["client_id"] != v["device_id"]
                or v["device_platform"] not in mapping or mapping[v["device_platform"]] != v["client_type"]
                or v["operation_deadline_unix_ms"] > v["device_enrollment_expires_at_unix_ms"]):
            _fail()
    return v  # DATA dict only. No SDK/task-owner/authority handle.


def _child(v):
    _keys(v, CHILD)
    _fields(v)
    if v["state"] != "CHILD_STATE" or v["outcome"] not in OUTCOMES:
        _fail()
    return v


def child_state(raw: bytes):
    v = decode(raw, 16384)
    if type(v) is dict and tuple(v) == ("version", "state") and v["state"] == "UNAVAILABLE":
        _fields(v)
        return v
    return _child(v)


def child_index(raw: bytes, max_children: int):
    # Required pure parser bound, not a live provider policy/default.
    if type(max_children) is not int or not 0 < max_children <= MAX:
        _fail()
    v = decode(raw, 65536)
    if type(v) is dict and tuple(v) == ("version", "state") and v["state"] == "UNAVAILABLE":
        _fields(v)
        return v
    _keys(v, ("version", "state", "pairing_epoch", "parent_enrollment_id",
              "parent_enrollment_generation", "A_body_sha256", "children"))
    _fields({k: x for k, x in v.items() if k != "children"})
    if v["state"] != "CHILD_INDEX" or type(v["children"]) is not list or len(v["children"]) > max_children:
        _fail()
    order = []
    for child in v["children"]:
        _child(child)
        if any(child[k] != v[k] for k in ("pairing_epoch", "parent_enrollment_id", "parent_enrollment_generation", "A_body_sha256")):
            _fail()
        order.append((child["child_id"], child["child_revision"]))
    if order != sorted(set(order)) or len({x[0] for x in order}) != len(order):
        _fail()
    return v


def _b64(text: str, limit: int):
    if type(text) is not str or re.fullmatch(r"[A-Za-z0-9_-]+", text) is None or len(text) > (limit * 4 + 2) // 3:
        _fail()
    try:
        decoded = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError:
        _fail()
    if len(decoded) > limit or base64.urlsafe_b64encode(decoded).decode().rstrip("=") != text:
        _fail()
    return decoded


def original_child_receipt(raw: bytes):
    v = decode(raw, 16384)  # Index override never applies to this route.
    if type(v) is dict and tuple(v) == ("version", "state") and v["state"] == "UNAVAILABLE":
        _fields(v)
        return v
    _keys(v, ("version", "state", "B_body_b64url", "B_signature_b64url"))
    if type(v["version"]) is not int or v["version"] != 1 or v["state"] != "CHILD_RECEIPT":
        _fail()
    body = _b64(v["B_body_b64url"], 8192)
    signature = _b64(v["B_signature_b64url"], 64)
    if len(signature) != 64:
        _fail()
    # Envelope bytes only, NOT signature verification or a validated B grant.
    return {"classification": "UNVERIFIED_RECEIPT_DATA_ONLY", "body": body, "signature": signature}
