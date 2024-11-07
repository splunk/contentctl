from __future__ import annotations
import re
from typing import List, Any
from pydantic import computed_field, Field, ConfigDict,model_serializer
from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.enums import DataModel
from contentctl.objects.investigation_tags import InvestigationTags
from contentctl.objects.constants import (
    CONTENTCTL_MAX_SEARCH_NAME_LENGTH,
    CONTENTCTL_RESPONSE_TASK_NAME_FORMAT_TEMPLATE,
    CONTENTCTL_MAX_STANZA_LENGTH
)
from contentctl.objects.config import CustomApp

# TODO (#266): disable the use_enum_values configuration
class Investigation(SecurityContentObject):
    model_config = ConfigDict(use_enum_values=True,validate_default=False)
    type: str = Field(...,pattern="^Investigation$")
    datamodel: list[DataModel] = Field(...)
    name:str = Field(...,max_length=CONTENTCTL_MAX_SEARCH_NAME_LENGTH)
    search: str = Field(...)
    how_to_implement: str = Field(...)
    known_false_positives: str = Field(...)
    
    
    tags: InvestigationTags

    # enrichment
    @computed_field
    @property
    def inputs(self)->List[str]:
        #Parse out and return all inputs from the searchj
        inputs:List[str] = []
        pattern = r"\$([^\s.]*)\$"

        for input in re.findall(pattern, self.search):
            inputs.append(str(input))

        return inputs

    @computed_field
    @property
    def lowercase_name(self)->str:
        return self.name.replace(' ', '_').replace('-','_').replace('.','_').replace('/','_').lower().replace(' ', '_').replace('-','_').replace('.','_').replace('/','_').lower()

    
    # This is a slightly modified version of the get_conf_stanza_name function from
    # SecurityContentObject_Abstract
    def get_response_task_name(self, app:CustomApp, max_stanza_length:int=CONTENTCTL_MAX_STANZA_LENGTH)->str:
        stanza_name = CONTENTCTL_RESPONSE_TASK_NAME_FORMAT_TEMPLATE.format(app_label=app.label, detection_name=self.name)
        if len(stanza_name) > max_stanza_length:
            raise ValueError(f"conf stanza may only be {max_stanza_length} characters, "
                             f"but stanza was actually {len(stanza_name)} characters: '{stanza_name}' ")
        return stanza_name
    

    @model_serializer
    def serialize_model(self):
        #Call serializer for parent
        super_fields = super().serialize_model()
        
        #All fields custom to this model
        model= {
            "type": self.type,
            "datamodel": self.datamodel,
            "search": self.search,
            "how_to_implement": self.how_to_implement,
            "known_false_positives": self.known_false_positives,
            "inputs": self.inputs,
            "tags": self.tags.model_dump(),
            "lowercase_name":self.lowercase_name
        }
        
        #Combine fields from this model with fields from parent
        super_fields.update(model)
        
        #return the model
        return super_fields


    def model_post_init(self, ctx:dict[str,Any]):
        # Ensure we link all stories this investigation references
        # back to itself
        for story in self.tags.analytic_story:
            story.investigations.append(self)
