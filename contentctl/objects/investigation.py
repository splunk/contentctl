from __future__ import annotations
import re
from typing import TYPE_CHECKING, Optional, List, Any
from pydantic import field_validator, computed_field, Field, ValidationInfo, ConfigDict,model_serializer
if TYPE_CHECKING:
    from contentctl.input.director import DirectorOutputDto
from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.enums import DataModel
from contentctl.objects.investigation_tags import InvestigationTags


class Investigation(SecurityContentObject):
    model_config = ConfigDict(use_enum_values=True,validate_default=False)
    type: str = Field(...,pattern="^Investigation$")
    datamodel: list[DataModel] = Field(...)
    
    search: str = Field(...)
    how_to_implement: str = Field(...)
    known_false_positives: str = Field(...)
    
    
    tags: InvestigationTags

    # enrichment
    @computed_field
    @property
    def inputs(self)->List[str]:
        #Parse out and return all inputs from the searchj
        inputs = []
        pattern = r"\$([^\s.]*)\$"

        for input in re.findall(pattern, self.search):
            inputs.append(input)

        return inputs

    @computed_field
    @property
    def lowercase_name(self)->str:
        return self.name.replace(' ', '_').replace('-','_').replace('.','_').replace('/','_').lower().replace(' ', '_').replace('-','_').replace('.','_').replace('/','_').lower()


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
        # director: Optional[DirectorOutputDto] = ctx.get("output_dto",None)
        # if not isinstance(director,DirectorOutputDto):
        #     raise ValueError("DirectorOutputDto was not passed in context of Detection model_post_init")
        director: Optional[DirectorOutputDto] = ctx.get("output_dto",None)
        for story in self.tags.analytic_story:
            story.investigations.append(self)
    

    