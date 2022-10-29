
import uuid
import string

from pydantic import BaseModel, validator, ValidationError

from splunk_contentctl.objects.security_content_object import SecurityContentObject
from splunk_contentctl.objects.playbook_tags import PlaybookTag



class Playbook(BaseModel, SecurityContentObject):
    name: str
    id: str
    version: int
    date: str
    author: str
    type: str
    description: str
    how_to_implement: str
    playbook: str
    check_references: bool = False #Validation is done in order, this field must be defined first
    references: list
    app_list: list
    tags: PlaybookTag


