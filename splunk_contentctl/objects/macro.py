

from pydantic import BaseModel, validator, ValidationError

from objects.security_content_object import SecurityContentObject



class Macro(BaseModel, SecurityContentObject):
    name: str
    definition: str
    description: str
    arguments: list = None
