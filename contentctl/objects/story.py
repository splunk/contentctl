import string
import uuid
import requests

from pydantic import BaseModel, validator, ValidationError
from datetime import datetime

from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.story_tags import StoryTags
from contentctl.helper.link_validator import LinkValidator
from contentctl.objects.enums import SecurityContentType
class Story(SecurityContentObject):
    # story spec
    #name: str
    #id: str
    #version: int
    #date: str
    #author: str
    #description: str
    #contentType: SecurityContentType = SecurityContentType.stories
    narrative: str
    check_references: bool = False #Validation is done in order, this field must be defined first
    references: list
    tags: StoryTags

    # enrichments
    detection_names: list = None
    investigation_names: list = None
    baseline_names: list = None
    author_company: str = None
    author_name: str = None
    detections: list = None
    investigations: list = None
    

    #Temporarily add back the analytic story name as a tag.
    #analytic_story name is no longer a memeber of tags since
    #its value was identical to name
    @validator('tags')
    def type_valid(cls, v, values):
        if v.analytic_story is None:
            v.analytic_story = values['name']

        return v

    # Allow long names for macros
    @validator('name',check_fields=False)
    def name_max_length(cls, v):
        #if len(v) > 67:
        #    raise ValueError('name is longer then 67 chars: ' + v)
        return v
    
    @validator('narrative')
    def encode_error(cls, v, values, field):
        return SecurityContentObject.free_text_field_valid(cls,v,values,field)

    @validator('references')
    def references_check(cls, v, values):
        return LinkValidator.SecurityContentObject_validate_references(v, values)