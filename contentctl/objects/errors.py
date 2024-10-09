from __future__ import annotations
from abc import ABC, abstractmethod
from pydantic import BaseModel, ConfigDict
from pydantic.dataclasses import dataclass
from uuid import UUID
from typing import Self, Sequence
from contentctl.output.yml_writer import YmlWriter
import pathlib
from contentctl.objects.constants import CONTENTCTL_MAX_STANZA_LENGTH

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
    # rule_name must be set in the _init_ functions of
    # individual exceptions, rather than here, because
    # it is used to calculate the long_message and 
    # short_message properties.
    rule_name: str

    # Determine whether or not this Exception 
    # should actually be treated as a WARNING 
    # rather than an Exception. This allows
    # individual Exceptions to be enabled or 
    # disabled based on command line flags
    suppress_as_warning: bool

    file_path: pathlib.Path

    def __init__(
            self,
            file_path: pathlib.Path,
            rule_name: str,
            suppress_as_warning: bool = False,
            *args: object
    ) -> None:
        print(f"file path in MVE: {file_path}")
        self.file_path = file_path,
        self.rule_name = rule_name
        self.suppress_as_warning = suppress_as_warning
        super().__init__(self.long_message, *args)

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
    
    @staticmethod
    @abstractmethod
    def error_plain_name() -> str:
        """
        A plain, English language name for the error
        :returns: a str, the message
        """
        raise NotImplementedError()
    
    def toJSON(self) -> dict[str, str | bool | UUID | int]:
        return {"rule_name": self.rule_name,
                "suppress_as_warning": self.suppress_as_warning,
                "short_message": self.short_message,
                "long_message": self.long_message,
                "file_path": str(self.file_path)}
    

    @classmethod
    def sort_and_filter(cls, errors: list[MetadataValidationError]) -> list[Self]:
        x = list(filter(lambda error: isinstance(error, cls), errors))
        return sorted(x, key = lambda e: (e.rule_name, e.suppress_as_warning))


class DetectionMissingError(MetadataValidationError):
    """
    An error indicating a detection in the prior build could not be found in the current build
    """
    def __init__(
            self,
            rule_name: str,
            suppress_as_warning: bool = False,
            *args: object
    ) -> None:
        self.rule_name = rule_name
        super().__init__(pathlib.Path("missing"), self.rule_name, suppress_as_warning, self.long_message, *args)

    @property
    def long_message(self) -> str:
        """
        A long-form error message
        :returns: a str, the message
        """
        return (
            f"'{self.rule_name}' in previous build not found in current build; "
            "detection may have been removed or renamed."
        )

    @property
    def short_message(self) -> str:
        """
        A short-form error message
        :returns: a str, the message
        """
        return (
            f"{self.rule_name.ljust(CONTENTCTL_MAX_STANZA_LENGTH)} from previous build not found in current build."
        )

    @staticmethod
    def error_plain_name() -> str:
        """
        A plain, English language name for the error
        :returns: a str, the message
        """
        return "Detection Missing Error"
    
    


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
            file_path:pathlib.Path,
            rule_name: str,
            current_id: UUID,
            previous_id: UUID,
            suppress_as_warning: bool = False,
            *args: object
    ) -> None:
        print(f"file path in DIDE: {file_path}")
        self.rule_name = rule_name
        self.current_id = current_id
        self.previous_id = previous_id
        super().__init__(file_path, self.rule_name, suppress_as_warning, self.long_message, *args)

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
            f"{self.rule_name.ljust(CONTENTCTL_MAX_STANZA_LENGTH)} with id {self.current_id} in current build does not match ID {self.previous_id} in previous build."
        )
    
    @staticmethod
    def error_plain_name() -> str:
        """
        A plain, English language name for the error
        :returns: a str, the message
        """
        return "Detection ID Error"

    def toJSON(self) -> dict[str, str | bool | UUID | int]:
        return super().toJSON() | {"current_id": self.current_id, 
                                   "previous_id": self.previous_id}

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
            file_path:pathlib.Path,
            rule_name: str,
            current_version: int,
            previous_version: int,
            suppress_as_warning: bool = False,
            *args: object
    ) -> None:
        print(f"file path in VE: {file_path}")
        self.rule_name = rule_name
        self.current_version = current_version
        self.previous_version = previous_version
        super().__init__(file_path, self.rule_name, suppress_as_warning, self.long_message, *args)

    def toJSON(self) -> dict[str, str | bool | UUID | int]:
        return super().toJSON() | {"current_version": self.current_version, 
                                   "previous_version": self.previous_version}


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
            f"{self.rule_name.ljust(CONTENTCTL_MAX_STANZA_LENGTH)} with version ({self.current_version}) in current build is less than version "
            f"({self.previous_version}) in previous build."
        )

    @staticmethod
    def error_plain_name() -> str:
        """
        A plain, English language name for the error
        :returns: a str, the message
        """
        return "Versioning Error"

    
class VersionBumpingError(VersioningError):
    """
    An error indicating the detection changed but its version wasn't bumped appropriately
    """

    @property
    def bumped_version(self) -> int:
        """
        Returns the verion that we should bump to.
        By default, we should bump one version above
        the previous_version. However, it is not considered
        an ERROR to bump more than 1 if done in the YML.

        Returns:
            int: previous_version + 1
        """
        return self.previous_version + 1

    @property
    def long_message(self) -> str:
        """
        A long-form error message
        :returns: a str, the message
        """
        return (
            f"Rule '{self.rule_name}' has changed in current build compared to previous "
            "build (stanza hashes differ); the detection version should be bumped "
            f"to at least {self.bumped_version}."
        )

    @property
    def short_message(self) -> str:
        """
        A short-form error message
        :returns: a str, the message
        """
        return (
            f"{self.rule_name.ljust(CONTENTCTL_MAX_STANZA_LENGTH)} version  must be bumped to at least {self.bumped_version}."
        )
    
    @staticmethod
    def error_plain_name() -> str:
        """
        A plain, English language name for the error
        :returns: a str, the message
        """
        return "Version Bumping Error"

    def toJSON(self) -> dict[str, str | bool | UUID | int]:
        return super().toJSON() | {"current_version": self.current_version, 
                                   "previous_version": self.previous_version, 
                                   "bumped_version": self.bumped_version}

class MetadataValidationErrorFile(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    detectionMissingErrors:list[DetectionMissingError] = []
    detectionIdErrors: list[DetectionIDError] = []
    versionDecrementedErrors: list[VersionDecrementedError] = []
    versionBumpingErrors: list[VersionBumpingError] = []

    @classmethod
    def parse_from_errors_list(cls, errors: list[MetadataValidationError]) -> Self:
        return cls(
            detectionMissingErrors=DetectionMissingError.sort_and_filter(errors),
            detectionIdErrors=DetectionIDError.sort_and_filter(errors),
            versionDecrementedErrors=VersionDecrementedError.sort_and_filter(errors),
            versionBumpingErrors=VersionBumpingError.sort_and_filter(errors),
        )
    
    def add_exception(self, exception:MetadataValidationError):
        if isinstance(exception, DetectionMissingError):
            self.detectionMissingErrors.append(exception)
        elif isinstance(exception, DetectionIDError):
            self.detectionIdErrors.append(exception)
        elif isinstance(exception, VersionDecrementedError):
            self.versionDecrementedErrors.append(exception)
        elif isinstance(exception, VersionBumpingError):
            self.versionBumpingErrors.append(exception)
        else:
            raise Exception("Unknown error type when generating "
                            f"Metadata Validation Error File - {type(exception)}")
    
    

    def cli_format_section(self, errors: Sequence[MetadataValidationError], section_name:str) -> str:
        """
        A header to print the the command line
        :returns: a str, the message
        """
        is_suppressed = True if True in [e.suppress_as_warning for e in errors] else False

        if is_suppressed:
            return f"{section_name} - {len(errors)} Suppressed Errors"
    
        header = f"{section_name} - {len(errors)} Errors"
        body = '\n  ❌'.join([""]+[error.short_message for error in errors])
        return f"{header}{body}"

    def print_errors(self):
        non_suppressed_errors = list(filter(lambda e: not e.suppress_as_warning, 
                                            self.detectionMissingErrors + 
                                            self.detectionIdErrors + 
                                            self.versionDecrementedErrors + 
                                            self.versionBumpingErrors))
        if len(non_suppressed_errors) == 0:
            print("\t✅ Detection metadata looks good and all versions were bumped appropriately :)")
        else:
            print(self.cli_format_section(self.detectionMissingErrors, DetectionMissingError.error_plain_name()))
            print(self.cli_format_section(self.detectionIdErrors, str(DetectionIDError.error_plain_name())))
            print(self.cli_format_section(self.versionDecrementedErrors, str(VersionDecrementedError.error_plain_name())))
            print(self.cli_format_section(self.versionBumpingErrors, str(VersionBumpingError.error_plain_name())))
        
                
            

    def write_to_file(self, output_file:pathlib.Path):
        output_dict:dict[str,list[dict[str, str | bool | UUID | int]]] = {}
        output_dict['detectionMissingErrors'] = [e.toJSON() for e in self.detectionMissingErrors]
        output_dict['detectionIdErrors'] = [e.toJSON() for e in self.detectionIdErrors]
        output_dict['versionDecrementedErrors'] = [e.toJSON() for e in self.versionDecrementedErrors]
        output_dict['versionBumpingErrors'] = [e.toJSON() for e in self.versionBumpingErrors]
        YmlWriter.writeYmlFile(str(output_file), output_dict)
    
            
