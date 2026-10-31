class InvalidTokenError(Exception):
    """The token is malformed, forged, expired, for another service or lacks a required claim."""
