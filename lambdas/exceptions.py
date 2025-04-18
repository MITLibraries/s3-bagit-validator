class AIPValidationError(Exception):
    """Raised when AIP validation fails."""

    def __init__(self, message: str, error_details: dict | None = None):
        """Initialize AIPValidationError with a message and optional error details.

        Args:
            message: Error message
            error_details: Dictionary with additional error details
        """
        super().__init__(message)
        self.error_details = error_details or {}
