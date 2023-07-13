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

     # Macro can have different punctuatuation in it,
    # so redefine the name validator. For now, jsut
    # allow any characters in the macro
    @validator('name',check_fields=False)
    def name_invalid_chars(cls, v):
        return v


    # Allow long names for lookups
    @validator('name',check_fields=False)
    def name_max_length(cls, v):
        #if len(v) > 67:
        #    raise ValueError('name is longer then 67 chars: ' + v)
        return v