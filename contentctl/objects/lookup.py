from pydantic import BaseModel, validator, ValidationError

from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.enums import SecurityContentType


class Lookup(SecurityContentObject):
    contentType: SecurityContentType = SecurityContentType.lookups
    #name: str
    #description: str
    collection: str = None
    fields_list: str = None
    filename: str = None
    default_match: str = None
    match_type: str = None
    min_matches: int = None
    case_sensitive_match: str = None
