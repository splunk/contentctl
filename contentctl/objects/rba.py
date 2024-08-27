import enum
from pydantic import BaseModel
from abc import ABC
from typing import Union, List



class RiskObjectType(str,enum.Enum):
    SYSTEM = "system"
    USER = "user"
    OTHER = "other"

class ThreatObjectType(str,enum.Enum):
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
    HTTP_USER_AGENT = "http_user_agent"
    IP_ADDRESS = "ip_address"
    PROCESS = "process"
    PROCESS_NAME = "process_name"
    PARENT_PROCESS = "parent_process"
    PARENT_PROCESS_NAME = "parent_process_name"
    PROCESS_HASH = "process_hash"
    REGISTRY_PATH = "registry_path"
    REGISTRY_VALUE_NAME = "registry_value_name"
    REGISTRY_VALUE_TEXT = "regstiry_value_text"
    SERVICE = "service"
    URL = "url"

class risk_object(BaseModel, ABC):
    field: str
    type: RiskObjectType
    score: int

class threat_object(BaseModel, ABC):
    field: str
    type: ThreatObjectType

class rba(BaseModel, ABC):
    message: str
    risk_objects: List[risk_object]
    threat_object: Union[List[threat_object], None]