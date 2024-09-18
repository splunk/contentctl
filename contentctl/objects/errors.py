from abc import ABC, abstractmethod
from uuid import UUID


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


class MetadataValidationError(Exception, ABC):
    """
    Base class for any errors arising from savedsearches.conf detection metadata validation
    """
    # The name of the rule the error relates to
    rule_name: str

    @property
    @abstractmethod
    def long_message(self) -> str:
        """
        A long-form error message
        :returns: a str, the message
        """
        raise NotImplementedError()

    @property
    @abstractmethod
    def short_message(self) -> str:
        """
        A short-form error message
        :returns: a str, the message
        """
        raise NotImplementedError()


class DetectionMissingError(MetadataValidationError):
    """
    An error indicating a detection in the prior build could not be found in the current build
    """
    def __init__(
            self,
            rule_name: str,
            *args: object
    ) -> None:
        self.rule_name = rule_name
        super().__init__(self.long_message, *args)

    @property
    def long_message(self) -> str:
        """
        A long-form error message
        :returns: a str, the message
        """
        return (
            f"Rule '{self.rule_name}' in previous build not found in current build; "
            "detection may have been removed or renamed."
        )

    @property
    def short_message(self) -> str:
        """
        A short-form error message
        :returns: a str, the message
        """
        return (
            "Detection from previous build not found in current build."
        )


class DetectionIDError(MetadataValidationError):
    """
    An error indicating the detection ID may have changed between builds
    """
    # The ID from the current build
    current_id: UUID

    # The ID from the previous build
    previous_id: UUID

    def __init__(
            self,
            rule_name: str,
            current_id: UUID,
            previous_id: UUID,
            *args: object
    ) -> None:
        self.rule_name = rule_name
        self.current_id = current_id
        self.previous_id = previous_id
        super().__init__(self.long_message, *args)

    @property
    def long_message(self) -> str:
        """
        A long-form error message
        :returns: a str, the message
        """
        return (
            f"Rule '{self.rule_name}' has ID {self.current_id} in current build "
            f"and {self.previous_id} in previous build; detection IDs and "
            "names should not change for the same detection between releases."
        )

    @property
    def short_message(self) -> str:
        """
        A short-form error message
        :returns: a str, the message
        """
        return (
            f"Detection ID {self.current_id} in current build does not match ID {self.previous_id} in previous build."
        )


class VersioningError(MetadataValidationError, ABC):
    """
    A base class for any metadata validation errors relating to detection versioning
    """
    # The version in the current build
    current_version: int

    # The version in the previous build
    previous_version: int

    def __init__(
            self,
            rule_name: str,
            current_version: int,
            previous_version: int,
            *args: object
    ) -> None:
        self.rule_name = rule_name
        self.current_version = current_version
        self.previous_version = previous_version
        super().__init__(self.long_message, *args)


class VersionDecrementedError(VersioningError):
    """
    An error indicating the version number went down between builds
    """
    @property
    def long_message(self) -> str:
        """
        A long-form error message
        :returns: a str, the message
        """
        return (
            f"Rule '{self.rule_name}' has version {self.current_version} in "
            f"current build and {self.previous_version} in previous build; "
            "detection versions cannot decrease in successive builds."
        )

    @property
    def short_message(self) -> str:
        """
        A short-form error message
        :returns: a str, the message
        """
        return (
            f"Detection version ({self.current_version}) in current build is less than version "
            f"({self.previous_version}) in previous build."
        )


class VersionBumpingError(VersioningError):
    """
    An error indicating the detection changed but its version wasn't bumped appropriately
    """
    @property
    def long_message(self) -> str:
        """
        A long-form error message
        :returns: a str, the message
        """
        return (
            f"Rule '{self.rule_name}' has changed in current build compared to previous "
            "build (stanza hashes differ); the detection version should be bumped "
            f"to at least {self.previous_version + 1}."
        )

    @property
    def short_message(self) -> str:
        """
        A short-form error message
        :returns: a str, the message
        """
        return (
            f"Detection version in current build should be bumped to at least {self.previous_version + 1}."
        )
