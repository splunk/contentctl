from enum import Enum
from pydantic import BaseModel
from abc import ABC
from typing import Set



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

class risk_object(BaseModel):
    field: str
    type: RiskObjectType
    score: int

    def __hash__(self):
        return hash((self.field, self.type, self.score))

class threat_object(BaseModel):
    field: str
    type: ThreatObjectType

    def __hash__(self):
        return hash((self.field, self.type))

class rba_object(BaseModel, ABC):
    message: str
    risk_objects: Set[risk_object] 
    threat_objects: Set[threat_object]
