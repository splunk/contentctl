from __future__ import annotations

from pydantic import BaseModel, validator, ValidationError
from typing import Tuple
import re
from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.enums import SecurityContentType

LOOKUPS_TO_IGNORE = set(["outputlookup"])
LOOKUPS_TO_IGNORE.add("ut_shannon_lookup") #In the URL toolbox app which is recommended for ESCU
LOOKUPS_TO_IGNORE.add("identity_lookup_expanded") #Shipped with the Asset and Identity Framework
LOOKUPS_TO_IGNORE.add("cim_corporate_web_domain_lookup") #Shipped with the Asset and Identity Framework
LOOKUPS_TO_IGNORE.add("alexa_lookup_by_str") #Shipped with the Asset and Identity Framework
LOOKUPS_TO_IGNORE.add("interesting_ports_lookup") #Shipped with the Asset and Identity Framework

#Special case for the Detection "Exploit Public Facing Application via Apache Commons Text"
LOOKUPS_TO_IGNORE.add("=") 
LOOKUPS_TO_IGNORE.add("other_lookups") 


class Lookup(BaseModel):
    #contentType: SecurityContentType = SecurityContentType.lookups
    name: str
    description: str
    collection: str = None
    fields_list: str = None
    filename: str = None
    default_match: str = None
    match_type: str = None
    min_matches: int = None
    case_sensitive_match: str = None
    file_path:str = None

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
    
    @staticmethod
    def get_lookups(text_field: str, all_lookups: list[Lookup], ignore_lookups:set[str]=LOOKUPS_TO_IGNORE)->Tuple[list[Lookup], set[str]]:
        lookups_to_get = set(re.findall(r'[^output]lookup (?:update=true)?(?:append=t)?\s*([^\s]*)', text_field))
        lookups_to_ignore = set([lookup for lookup in lookups_to_get if any(to_ignore in lookups_to_get for to_ignore in ignore_lookups)])
        lookups_to_get -= lookups_to_ignore
        found_lookups, missing_lookups = SecurityContentObject.get_objects_by_name(lookups_to_get, all_lookups)
        return found_lookups, missing_lookups
    