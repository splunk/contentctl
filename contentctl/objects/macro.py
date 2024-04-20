# Used so that we can have a staticmethod that takes the class 
# type Macro as an argument
from __future__ import annotations
from typing import TYPE_CHECKING, List
import re
from pydantic import Field, model_serializer
if TYPE_CHECKING:
    from contentctl.input.director import DirectorOutputDto
from contentctl.objects.security_content_object import SecurityContentObject



MACROS_TO_IGNORE = set(["_filter", "drop_dm_object_name"])
#Should all of the following be included as well?
MACROS_TO_IGNORE.add("get_asset" )
MACROS_TO_IGNORE.add("get_risk_severity")
MACROS_TO_IGNORE.add("cim_corporate_web_domain_search")
MACROS_TO_IGNORE.add("prohibited_processes")


class Macro(SecurityContentObject):
    definition: str = Field(..., min_length=1)
    arguments: List[str] = Field([])
    
    


    @model_serializer
    def serialize_model(self):
        #DO NOT Call serializer for parent - this will include extra fields we do not want
        #super_fields = super().serialize_model()

        #All fields custom to this model
        model= {
            "name": self.name,
            "definition": self.definition,
            "description": self.description,
            "arguments": self.arguments
        }
        
        #return the model
        return model
    
    @staticmethod
    def get_macros(text_field:str, director:DirectorOutputDto , ignore_macros:set[str]=MACROS_TO_IGNORE)->list[Macro]:
                
        #Simple regex to remove comments which can cause issues with
        #the macro pasing logic below
        text_field = re.sub(r'```.*```', ' ', text_field)
                
        macros_to_get = re.findall(r'`([^\s]+)`', text_field)
        #If macros take arguments, stop at the first argument.  We just want the name of the macro
        macros_to_get = set([macro[:macro.find('(')] if macro.find('(') != -1 else macro for macro in macros_to_get])
        
        macros_to_ignore = set([macro for macro in macros_to_get if any(to_ignore in macro for to_ignore in ignore_macros)])
        #remove the ones that we will ignore
        macros_to_get -= macros_to_ignore
        return Macro.mapNamesToSecurityContentObjects(list(macros_to_get), director)
        
    