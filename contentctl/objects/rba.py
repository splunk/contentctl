from __future__ import annotations

from abc import ABC
from enum import Enum
from typing import Annotated, Set

from pydantic import BaseModel, Field, computed_field, model_serializer

from contentctl.objects.enums import RiskSeverity

RiskScoreValue_Type = Annotated[int, Field(ge=1, le=100)]


class RiskObjectType(str, Enum):
    SYSTEM = "system"
    USER = "user"
    OTHER = "other"


class ThreatObjectType(str, Enum):
    CERTIFICATE_COMMON_NAME = "certificate_common_name"
    CERTIFICATE_ORGANIZATION = "certificate_organization"
    CERTIFICATE_SERIAL = "certificate_serial"
    CERTIFICATE_UNIT = "certificate_unit"
    COMMAND = "command"
    DOMAIN = "domain"
    EMAIL_ADDRESS = "email_address"
    EMAIL_SUBJECT = "email_subject"
    FILE_HASH = "file_hash"
    FILE_NAME = "file_name"
    FILE_PATH = "file_path"
    HTTP_USER_AGENT = "http_user_agent"
    IP_ADDRESS = "ip_address"
    PROCESS = "process"
    PROCESS_NAME = "process_name"
    PARENT_PROCESS = "parent_process"
    PARENT_PROCESS_NAME = "parent_process_name"
    PROCESS_HASH = "process_hash"
    REGISTRY_PATH = "registry_path"
    REGISTRY_VALUE_NAME = "registry_value_name"
    REGISTRY_VALUE_TEXT = "registry_value_text"
    SERVICE = "service"
    SIGNATURE = "signature"
    SYSTEM = "system"
    TLS_HASH = "tls_hash"
    URL = "url"


class RiskObject(BaseModel):
    field: str
    type: RiskObjectType
    score: RiskScoreValue_Type

    def __hash__(self):
        return hash((self.field, self.type, self.score))

    def __lt__(self, other: RiskObject) -> bool:
        if (
            f"{self.field}{self.type}{self.score}"
            < f"{other.field}{other.type}{other.score}"
        ):
            return True
        return False

    @model_serializer
    def serialize_risk_object(self) -> dict[str, str | int]:
        """
        We define this explicitly for two reasons, even though the automatic
        serialization works correctly.  First we want to enforce a specific
        field order for reasons of readability. Second, some of the fields
        actually have different names than they do in the object.
        """
        return {
            "risk_object_field": self.field,
            "risk_object_type": self.type,
            "risk_score": self.score,
        }


class ThreatObject(BaseModel):
    field: str
    type: ThreatObjectType

    def __hash__(self):
        return hash((self.field, self.type))

    def __lt__(self, other: ThreatObject) -> bool:
        if f"{self.field}{self.type}" < f"{other.field}{other.type}":
            return True
        return False

    @model_serializer
    def serialize_threat_object(self) -> dict[str, str]:
        """
        We define this explicitly for two reasons, even though the automatic
        serialization works correctly.  First we want to enforce a specific
        field order for reasons of readability. Second, some of the fields
        actually have different names than they do in the object.
        """
        return {
            "threat_object_field": self.field,
            "threat_object_type": self.type,
        }


class RBAObject(BaseModel, ABC):
    message: str
    risk_objects: Annotated[Set[RiskObject], Field(min_length=1)]
    threat_objects: Set[ThreatObject]

    @computed_field
    @property
    def risk_score(self) -> RiskScoreValue_Type:
        # First get the maximum score associated with
        # a risk object. If there are no objects, then
        # we should throw an exception.
        if len(self.risk_objects) == 0:
            raise Exception(
                "There must be at least one Risk Object present to get Severity."
            )
        return max([risk_object.score for risk_object in self.risk_objects])

    @computed_field
    @property
    def severity(self) -> RiskSeverity:
        if 0 <= self.risk_score <= 20:
            return RiskSeverity.INFORMATIONAL
        elif 20 < self.risk_score <= 40:
            return RiskSeverity.LOW
        elif 40 < self.risk_score <= 60:
            return RiskSeverity.MEDIUM
        elif 60 < self.risk_score <= 80:
            return RiskSeverity.HIGH
        elif 80 < self.risk_score <= 100:
            return RiskSeverity.CRITICAL
        else:
            raise Exception(
                f"Error getting severity - risk_score must be between 0-100, but was actually {self.risk_score}"
            )

    @model_serializer
    def serialize_rba(self) -> dict[str, str | list[dict[str, str | int]]]:
        return {
            "message": self.message,
            "risk_objects": [obj.model_dump() for obj in sorted(self.risk_objects)],
            "threat_objects": [obj.model_dump() for obj in sorted(self.threat_objects)],
        }
