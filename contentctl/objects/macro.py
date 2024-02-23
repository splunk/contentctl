# Used so that we can have a staticmethod that takes the class 
# type Macro as an argument
from __future__ import annotations
import re
from pydantic import BaseModel, validator, ValidationError

from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.enums import SecurityContentType
from typing import Tuple


MACROS_TO_IGNORE = set(["_filter", "drop_dm_object_name"])
#Should all of the following be included as well?
MACROS_TO_IGNORE.add("get_asset" )
MACROS_TO_IGNORE.add("get_risk_severity")
MACROS_TO_IGNORE.add("cim_corporate_web_domain_search")
MACROS_TO_IGNORE.add("prohibited_processes")


class Macro(BaseModel):
    #contentType: SecurityContentType = SecurityContentType.macros
    name: str
    definition: str
    description: str
    arguments: list = None
    file_path: str = None

    # Macro can have different punctuatuation in it,
    # so redefine the name validator. For now, jsut
    # allow any characters in the macro
    @validator('name',check_fields=False)
    def name_invalid_chars(cls, v):
        return v


    # Allow long names for macros
    @validator('name',check_fields=False)
    def name_max_length(cls, v):
        #if len(v) > 67:
        #    raise ValueError('name is longer then 67 chars: ' + v)
        return v

    
    @staticmethod
    def get_macros(text_field:str, all_macros: list[Macro], ignore_macros:set[str]=MACROS_TO_IGNORE)->Tuple[list[Macro], set[str]]:
        #Remove any comments, allowing there to be macros (which have a single backtick) inside those comments
        #If a comment ENDS in a macro, for example ```this is a comment with a macro `macro_here````
        #then there is a small edge case where the regex below does not work properly.  If that is 
        #the case, we edit the search slightly to insert a space
        text_field = re.sub(r"\`\`\`\`", r"` ```", text_field)
        text_field = re.sub(r"\`\`\`.*?\`\`\`", " ", text_field)
        
        macros_to_get = re.findall(r'`([^\s]+)`', text_field)
        #If macros take arguments, stop at the first argument.  We just want the name of the macro
        macros_to_get = set([macro[:macro.find('(')] if macro.find('(') != -1 else macro for macro in macros_to_get])
        
        macros_to_ignore = set([macro for macro in macros_to_get if any(to_ignore in macro for to_ignore in ignore_macros)])
        #remove the ones that we will ignore
        macros_to_get -= macros_to_ignore
        found_macros, missing_macros = SecurityContentObject.get_objects_by_name(macros_to_get, all_macros)
        return found_macros, missing_macros

        # found_macros = [macro for macro in all_macros if macro.name in macros_to_get]
        
        # missing_macros = macros_to_get - set([macro.name for macro in found_macros])
        # missing_macros_after_ignored_macros = set()
        # for macro in missing_macros:
        #     found = False
        #     for ignore in ignore_macros:
        #         if ignore in macro:
        #             found=True
        #             break
        #     if found is False:
        #         missing_macros_after_ignored_macros.add(macro)

        #return found_macros, missing_macros_after_ignored_macros
        



