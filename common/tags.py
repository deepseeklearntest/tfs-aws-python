"""
Shared, stdlib-only tag lookup helpers.

Deliberately has no boto3/botocore import so it is safe to import from any
script regardless of truststore/SSL injection ordering (see CLAUDE.md's
"botocore.config must be imported after common.session" note).
"""
from __future__ import annotations

# Owner tag aliases, matched case-insensitively. A superset of the
# TAG_ALIASES['application_owner'] set in continuous/43_detect_tagging_compliance.py
# (that script also treats any case variant of the canonical 'application_owner'
# key as a match, so the two vocabularies cover the same tag space) so owner
# attribution stays consistent across scripts.
OWNER_TAG_KEYS = (
    'Owner',
    'resource_owner',
    'team_owner',
    'application_owner',
    'ApplicationOwner',
)


def normalize_key(key: str) -> str:
    """Lowercase and strip separators so 'Application Owner', 'application-owner',
    and 'application_owner' are all treated as the same key. Real-world tagging
    across this org is inconsistent about which separator (or none) is used.

    Public so other modules with their own tag-key lookup tables (e.g.
    common/findings_io.py's _TAG_KEY_MAP, continuous/43_detect_tagging_compliance.py's
    _ALIAS_LOOKUP) can normalize against the same rule instead of duplicating it.
    """
    return key.strip().lower().replace(' ', '').replace('-', '').replace('_', '')


def tag_value(tags: list[dict] | dict | None, key: str) -> str:
    """Return the Value for the first tag matching `key`, or ''.

    Matching is case- and separator-insensitive (see normalize_key) since real
    tag keys vary between spaces, dashes, and underscores for the same concept.
    Accepts an AWS tag list [{'Key': ..., 'Value': ...}, ...], a plain
    {key: value} dict, or None.
    """
    if not tags:
        return ''
    target = normalize_key(key)
    if isinstance(tags, dict):
        for k, v in tags.items():
            if normalize_key(k) == target:
                return v
        return ''
    for tag in tags:
        if normalize_key(tag.get('Key', '')) == target:
            return tag.get('Value', '')
    return ''


def owner_from_tags(tags: list[dict] | dict | None, candidates: tuple[str, ...] = OWNER_TAG_KEYS) -> str:
    """Return the first non-empty owner tag value among `candidates`, or ''.

    Candidate keys are matched case- and separator-insensitively (see
    normalize_key) and tried in order.
    A whitespace-only value is treated as absent (mirrors the non-empty-value
    check in continuous/43_detect_tagging_compliance.py's _resolve_tags).
    """
    for key in candidates:
        value = tag_value(tags, key).strip()
        if value:
            return value
    return ''
