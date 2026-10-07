class AegisScanError(Exception):
    """Base class for expected AegisScan user-facing errors."""


class ConfigurationError(AegisScanError):
    """Raised when AegisScan configuration is invalid."""


class ParseError(AegisScanError):
    """Raised when a supported configuration file cannot be parsed."""
