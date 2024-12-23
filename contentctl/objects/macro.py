# Used so that we can have a staticmethod that takes the class 
# type Macro as an argument
from __future__ import annotations
from typing import TYPE_CHECKING, List
import re
from pydantic import Field, model_serializer, NonNegativeInt
import uuid
import datetime
if TYPE_CHECKING:
    from contentctl.input.director import DirectorOutputDto
from contentctl.objects.security_content_object import SecurityContentObject

#The following macros are included in commonly-installed apps.
#As such, we will ignore if they are missing from our app.
#Included in 
MACROS_TO_IGNORE = set(["drop_dm_object_name"]) # Part of CIM/Splunk_SA_CIM
MACROS_TO_IGNORE.add("get_asset") #SA-IdentityManagement, part of Enterprise Security
MACROS_TO_IGNORE.add("get_risk_severity") #SA-ThreatIntelligence, part of Enterprise Security
MACROS_TO_IGNORE.add("cim_corporate_web_domain_search") #Part of CIM/Splunk_SA_CIM
#MACROS_TO_IGNORE.add("prohibited_processes")


class Macro(SecurityContentObject):
    definition: str = Field(..., min_length=1)
    arguments: List[str] = Field([])
    # TODO: Add id field to all macro ymls
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    date: datetime.date = Field(datetime.date.today())
    author: str = Field("NO AUTHOR DEFINED",max_length=255)
    version: NonNegativeInt = 1
    


    @model_serializer
    def serialize_model(self):
        #Call serializer for parent
        super_fields = super().serialize_model()

        #All fields custom to this model
        model= {
            "definition": self.definition,
            "description": self.description,
        }
        
        #return the model
        model.update(super_fields)
        
        return model
    
    @staticmethod

    def get_macros(text_field:str, director:DirectorOutputDto , ignore_macros:set[str]=MACROS_TO_IGNORE)->list[Macro]:
        #Remove any comments, allowing there to be macros (which have a single backtick) inside those comments
        #If a comment ENDS in a macro, for example ```this is a comment with a macro `macro_here````
        #then there is a small edge case where the regex below does not work properly.  If that is 
        #the case, we edit the search slightly to insert a space
        if re.findall(r"\`\`\`\`", text_field):
            raise ValueError("Search contained four or more '`' characters in a row which is invalid SPL"
                            "This may have occurred when a macro was commented out.\n"
                            "Please ammend your search to remove the substring '````'")

        # replace all the macros with a space    
        text_field = re.sub(r"\`\`\`[\s\S]*?\`\`\`", " ", text_field) 
        
        
        macros_to_get = re.findall(r'`([^\s]+)`', text_field)
        #If macros take arguments, stop at the first argument.  We just want the name of the macro
        macros_to_get = set([macro[:macro.find('(')] if macro.find('(') != -1 else macro for macro in macros_to_get])
        
        macros_to_ignore = set([macro for macro in macros_to_get if any(to_ignore in macro for to_ignore in ignore_macros)])
        #remove the ones that we will ignore
        macros_to_get -= macros_to_ignore
        return Macro.mapNamesToSecurityContentObjects(list(macros_to_get), director)
        
