from __future__ import annotations

from pydantic import BaseModel, validator, ValidationError, field_validator, ValidationInfo, model_validator, FilePath
from typing import Tuple, Optional, Any, Union
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


class Lookup(SecurityContentObject):
    
    collection: Optional[str] = None
    fields_list: Optional[str] = None
    filename: Optional[FilePath] = None
    default_match: Optional[bool] = None
    match_type: Optional[str] = None
    min_matches: Optional[int] = None
    case_sensitive_match: Optional[bool] = None
    

    @model_validator(mode="before")
    def fix_lookup_path(cls, data:Any)->Any:
        if data.get("filename"):
            data["filename"] = "lookups/" + data["filename"]
        return data

    @field_validator('filename')
    @classmethod
    def lookup_file_valid(cls, v: Union[FilePath,None], info: ValidationInfo):
        if not v:
            return v
        if not (v.name.endswith(".csv") or v.name.endswith(".mlmodel")):
            raise ValueError(f"All Lookup files must be CSV files and end in .csv.  The following file does not: '{v}'")

        return v
        
    @field_validator('match_type')
    @classmethod
    def match_type_valid(cls, v: Union[str,None], info: ValidationInfo):
        if not v:
            #Match type can be None and that's okay
            return v

        if not (v.startswith("WILDCARD(") or v.endswith(")")) :
            raise ValueError(f"All match_types must take the format 'WILDCARD(field_name)'. The following file does not: '{v}'")
        return v


    #Ensure that exactly one of location or filename are defined
    @model_validator(mode='after')
    def ensure_mutually_exclusive_fields(self)->Lookup:
        if self.filename is not None and self.collection is not None:
            raise ValueError("filename and collection cannot be defined in the lookup file.  Exactly one must be defined.")
        elif self.filename is None and self.collection is None:
            raise ValueError("Neither filename nor collection were defined in the lookup file.  Exactly one must "
                             "be defined.")


        return self
    
    
    @staticmethod
    def get_lookups(text_field: str, all_lookups: list[Lookup], ignore_lookups:set[str]=LOOKUPS_TO_IGNORE)->Tuple[list[Lookup], set[str]]:
        lookups_to_get = set(re.findall(r'[^output]lookup (?:update=true)?(?:append=t)?\s*([^\s]*)', text_field))
        lookups_to_ignore = set([lookup for lookup in lookups_to_get if any(to_ignore in lookups_to_get for to_ignore in ignore_lookups)])
        lookups_to_get -= lookups_to_ignore
        found_lookups, missing_lookups = SecurityContentObject.get_objects_by_name(lookups_to_get, all_lookups)
        return found_lookups, missing_lookups
    