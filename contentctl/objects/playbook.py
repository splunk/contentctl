
import uuid
import string

from pydantic import BaseModel, validator, ValidationError

from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.playbook_tags import PlaybookTag
from contentctl.helper.link_validator import LinkValidator
from contentctl.objects.enums import SecurityContentType


class Playbook(SecurityContentObject):
    #name: str
    #id: str
    #version: int
    #date: str
    #author: str
    contentType: SecurityContentType = SecurityContentType.playbooks
    type: str
    #description: str
    how_to_implement: str
    playbook: str
    check_references: bool = False #Validation is done in order, this field must be defined first
    references: list
    app_list: list
    tags: PlaybookTag


    @validator('references')
    def references_check(cls, v, values):
        return LinkValidator.SecurityContentObject_validate_references(v, values)