from __future__ import annotations
from typing import TYPE_CHECKING, Optional, List
from pydantic import field_validator, computed_field, Field, ValidationInfo, ConfigDict
if TYPE_CHECKING:
    from contentctl.input.director import DirectorOutputDto
from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.enums import DataModel
from contentctl.objects.investigation_tags import InvestigationTags


class Investigation(SecurityContentObject):
    model_config = ConfigDict(use_enum_values=True,validate_default=False)
    name: str = Field(max_length=75)
    type: str = Field(...,pattern="^Investigation$")
    datamodel: list[DataModel] = Field(...)
    
    search: str = Field(...)
    how_to_implement: str = Field(...)
    known_false_positives: str = Field(...)
    check_references: bool = False #Validation is done in order, this field must be defined first
    inputs: Optional[List[str]] = None
    tags: InvestigationTags

    # enrichment
    @computed_field
    @property
    def lowercase_name(self)->str:
        return self.name.replace(' ', '_').replace('-','_').replace('.','_').replace('/','_').lower().replace(' ', '_').replace('-','_').replace('.','_').replace('/','_').lower()


    def model_post_init(self, ctx:dict[str,Any]):
        # director: Optional[DirectorOutputDto] = ctx.get("output_dto",None)
        # if not isinstance(director,DirectorOutputDto):
        #     raise ValueError("DirectorOutputDto was not passed in context of Detection model_post_init")
        director: Optional[DirectorOutputDto] = ctx.get("output_dto",None)
        for story in self.tags.analytic_story:
            story.investigations.append(self)
    


    @field_validator('how_to_implement', 'known_false_positives')
    @classmethod
    def encode_error(cls, v: str, info: ValidationInfo):
        return SecurityContentObject.free_text_field_valid(v,info)

    