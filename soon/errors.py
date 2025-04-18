class DoesNotExistException(Exception):
    """Raised when something does not exist"""


class AlreadyIsException(Exception):
    """Raised when something already is/exist"""


class FileException(Exception):
    """Raised when a file operation is not possible"""


class IdentityException(Exception):
    """Raised to wrap exceptions originating from external modules."""

class ActionException(Exception):
    """Raised when the action is not completed"""