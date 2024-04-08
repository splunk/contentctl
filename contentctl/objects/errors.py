class ValidationFailed(Exception):
    """Indicates not an error in execution, but a validation failure"""
    pass


class IntegrationTestingError(Exception):
    """Base exception class for integration testing"""
    pass


class ServerError(IntegrationTestingError):
    """An error encounterd during integration testing, as provided by the server (Splunk instance)"""
    pass


class ClientError(IntegrationTestingError):
    """An error encounterd during integration testing, on the client's side (locally)"""
    pass
