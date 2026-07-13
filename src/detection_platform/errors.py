"""Expected domain failures with safe user-facing diagnostics."""


class DetectionPlatformError(Exception):
    """Base class for validation and execution failures."""


class ValidationError(DetectionPlatformError):
    """A rule, corpus, or configuration is invalid."""


class UnsupportedSyntaxError(ValidationError):
    """A rule uses syntax outside the documented execution subset."""


class IntegrityError(DetectionPlatformError):
    """A vendored dataset or audit chain failed integrity verification."""
