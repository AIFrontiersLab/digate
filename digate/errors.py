"""Domain errors for Digate."""


class DigateError(Exception):
    """Base Digate error."""


class KeyError_(DigateError):
    """Signing or verification key problem."""


class VerdictError(DigateError):
    """Signed verdict is malformed or unusable."""


class PromotionDenied(DigateError):
    """Promotion request rejected by the gateway."""

    def __init__(self, reason: str, *, code: str = "denied") -> None:
        super().__init__(reason)
        self.reason = reason
        self.code = code


class StoreConflict(DigateError):
    """Release state changed underfoot."""
