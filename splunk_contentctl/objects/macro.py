

from pydantic import BaseModel, validator, ValidationError

from splunk_contentctl.objects.security_content_object import SecurityContentObject



class Macro(BaseModel, SecurityContentObject):
    name: str
    definition: str
    description: str
    arguments: list = None
