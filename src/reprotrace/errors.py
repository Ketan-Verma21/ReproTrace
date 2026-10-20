"""Exception hierarchy for ReproTrace.

Every expected failure carries a process exit code and an optional one-line hint so the
CLI can print a short message without a stack trace.
"""

EXIT_GENERAL_ERROR = 1
EXIT_ENVIRONMENT_ERROR = 2


class ReproTraceError(Exception):
    """Base class for all ReproTrace errors."""

    default_exit_code = EXIT_GENERAL_ERROR

    def __init__(self, message: str, hint: str | None = None, exit_code: int | None = None):
        super().__init__(message)
        self.message = message
        self.hint = hint
        self.exit_code = self.default_exit_code if exit_code is None else exit_code


class CaptureError(ReproTraceError):
    """Capturing a trace was not possible (missing strace, no ptrace permission, ...)."""


class ParseError(ReproTraceError):
    """Internal parser invariant violated. Malformed trace lines never raise this."""


class StoreError(ReproTraceError):
    """Reading or writing saved run data failed."""


class SchemaVersionError(ReproTraceError):
    """Stored data has an unknown or unsupported schema version."""


class AIError(ReproTraceError):
    """The optional AI explanation layer failed."""
