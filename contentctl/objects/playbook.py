
import uuid
import string

from pydantic import BaseModel, validator, ValidationError
from datetime import datetime, timedelta

from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.playbook_tags import PlaybookTag



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

    # enrichments
    file_name: str = None


    @validator("name")
    def name_invalid_chars(cls, v):
        allowedChars = set(string.ascii_lowercase + string.ascii_uppercase + string.digits + ' ')
        for char in v:
            if char not in allowedChars:
                raise ValueError("invalid char " + char + " used in name: " + v)
        return v

    @validator("id")
    def id_check(cls, v, values):
        try:
            uuid.UUID(str(v))
        except:
            raise ValueError("uuid is not valid: " + values["name"])
        return v

    @validator("date")
    def date_valid(cls, v, values):
        try:
            datetime.strptime(v, "%Y-%m-%d")
        except:
            raise ValueError("date is not in format YYYY-MM-DD: " + values["name"])
        return v

    @validator("type")
    def type_valid(cls, v, values):
        if v not in ["Investigation", "Response"]
            raise ValueError("type field is not Investigation or Response for playbook: " + values["name"])
        return v

    @validator("description", "how_to_implement")
    def encode_error(cls, v, values, field):
        try:
            v.encode("ascii")
        except UnicodeEncodeError:
            raise ValueError("encoding error in " + field.name + ": " + values["name"])
        return v

    @validator("file_name", "playbook")
    def file_name_invalid_chars(cls, v, values):
        allowedChars = set(string.ascii_lowercase + string.ascii_uppercase + string.digits + '_')
        for char in v:
            if char not in allowedChars:
                raise ValueError("invalid char " + char + " used in name: " + values["name"])
        return v