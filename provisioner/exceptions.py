"""Exception hierarchy. Each error carries the HTTP status the API should return."""


class ProvisionerError(Exception):
    status = 500

    def __init__(self, message, details=None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_dict(self):
        body = {"error": type(self).__name__, "message": self.message}
        if self.details:
            body["details"] = self.details
        return body


class ValidationError(ProvisionerError):
    status = 400


class NotFoundError(ProvisionerError):
    status = 404


class ConflictError(ProvisionerError):
    status = 409


class AuthError(ProvisionerError):
    status = 401


class ExecutionError(ProvisionerError):
    status = 500
