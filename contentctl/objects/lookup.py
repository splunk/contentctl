from __future__ import annotations
from pydantic import field_validator, ValidationInfo, model_validator, FilePath, model_serializer
from typing import TYPE_CHECKING, Optional, Any, Union
import re
if TYPE_CHECKING:
    from contentctl.input.director import DirectorOutputDto
    from contentctl.objects.config import validate
from contentctl.objects.security_content_object import SecurityContentObject


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
    

    @model_serializer
    def serialize_model(self):
        #Call parent serializer
        super_fields = super().serialize_model()

        #All fields custom to this model
        model= {
            "filename": self.filename.name if self.filename is not None else None,
            "default_match": "true" if self.default_match is True else "false",
            "match_type": self.match_type,
            "min_matches": self.min_matches,
            "case_sensitive_match": "true" if self.case_sensitive_match is True else "false",
            "collection": self.collection,
            "fields_list": self.fields_list
        }
        
        #return the model
        model.update(super_fields)
        return model

    @model_validator(mode="before")
    def fix_lookup_path(cls, data:Any, info: ValidationInfo)->Any:
        if data.get("filename"):
            config:validate = info.context.get("config",None)
            if config is not None:
                data["filename"] = config.path / "lookups/" / data["filename"]
            else:
                raise ValueError("config required for constructing lookup filename, but it was not")
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
    def get_lookups(text_field: str, director:DirectorOutputDto, ignore_lookups:set[str]=LOOKUPS_TO_IGNORE)->list[Lookup]:
        lookups_to_get = set(re.findall(r'[^output]lookup (?:update=true)?(?:append=t)?\s*([^\s]*)', text_field))
        lookups_to_ignore = set([lookup for lookup in lookups_to_get if any(to_ignore in lookups_to_get for to_ignore in ignore_lookups)])
        lookups_to_get -= lookups_to_ignore
        return Lookup.mapNamesToSecurityContentObjects(list(lookups_to_get), director)
    