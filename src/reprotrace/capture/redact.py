"""Redaction of secrets in environment variables before they are stored or shown."""

import re

REDACTED = "<redacted>"

_SECRET_KEY = re.compile(r"KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH", re.IGNORECASE)

_TOKEN_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}"),  # GitHub tokens
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}"),  # OpenAI / Anthropic style keys
    re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"),  # Slack tokens
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"),  # JWT
)

# Long opaque strings with letters and digits look like tokens. "/" and ":" are excluded
# from the character class so long paths and PATH-like lists are not redacted.
_OPAQUE_VALUE = re.compile(r"^(?=.*[A-Za-z])(?=.*[0-9])[A-Za-z0-9+=_\-.]{32,}$")

# Credentials embedded in URLs, e.g. https://user:pass@host
_URL_PASSWORD = re.compile(r"(?P<prefix>[a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@]+:)[^/\s@]+@")


def is_secret_key(key: str) -> bool:
    """Return True if an environment variable name suggests it holds a secret."""
    return bool(_SECRET_KEY.search(key))


def looks_like_token(value: str) -> bool:
    """Return True if a value looks like an access token or key."""
    if _OPAQUE_VALUE.match(value):
        return True
    return any(pattern.search(value) for pattern in _TOKEN_VALUE_PATTERNS)


def redact_value(value: str) -> str:
    """Redact URL passwords inside a value; leave the rest readable."""
    return _URL_PASSWORD.sub(lambda m: f"{m.group('prefix')}{REDACTED}@", value)


def redact_env(env: dict[str, str]) -> dict[str, str]:
    """Return a copy of ``env`` with secret-looking values replaced, sorted by key."""
    redacted: dict[str, str] = {}
    for key in sorted(env):
        value = env[key]
        if is_secret_key(key) or looks_like_token(value):
            redacted[key] = REDACTED
        else:
            redacted[key] = redact_value(value)
    return redacted
