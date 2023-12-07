
import uuid
import string

from pydantic import BaseModel, field_validator, ValidationInfo, ValidationError, Field

from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.playbook_tags import PlaybookTag
from contentctl.helper.link_validator import LinkValidator
from contentctl.objects.enums import SecurityContentType, PlaybookType


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

    