from pydantic import field_validator, ValidationInfo, Field

from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.playbook_tags import PlaybookTag

from contentctl.objects.enums import PlaybookType


class Playbook(SecurityContentObject):
    type: PlaybookType = ...
    how_to_implement: str = ...
    playbook: str = ...
    app_list: list[str] = Field(...,min_length=0) 
    tags: PlaybookTag = ...


    @field_validator('how_to_implement')
    @classmethod
    def encode_error(cls, v:str, info:ValidationInfo):
        return super().free_text_field_valid(v,info)

    