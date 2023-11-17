from __future__ import annotations
import re
import abc
import string
import uuid
from datetime import datetime
from pydantic import BaseModel, validator, ValidationError, Field
from contentctl.objects.enums import SecurityContentType
from typing import Tuple

import uuid
import pathlib

NO_FILE_BUILT_AT_RUNTIME = "NO_FILE_BUILT_AT_RUNTIME"
class SecurityContentObject_Abstract(BaseModel, abc.ABC):
    #contentType: SecurityContentType
    name: str
    author: str = "UNKNOWN_AUTHOR"
    date: str = "1990-01-01"
    version: int = 1
    id: uuid.UUID = Field(default_factory=uuid.uuid4) #we set a default here until all content has a uuid
    description: str = "UNKNOWN_DESCRIPTION"
    file_path: str = "NO_FILE_BUILT_AT_RUNTIME"

    @validator('name')
    def name_max_length(cls, v):
        if len(v) > 67:
            raise ValueError('name is longer then 67 chars: ' + v)
        return v

    @validator('name')
    def name_invalid_chars(cls, v):
        invalidChars = set(string.punctuation.replace("-", ""))
        if any(char in invalidChars for char in v):
            raise ValueError('invalid chars used in name: ' + v)
        return v

    @validator('date')
    def date_valid(cls, v, values):
        try:
            datetime.strptime(v, "%Y-%m-%d")
        except:
            raise ValueError('date is not in format YYYY-MM-DD: ' + values["name"])
        return v

    @staticmethod
    def free_text_field_valid(input_cls, v, values, field):
        try:
            v.encode('ascii')
        except UnicodeEncodeError as e:
            print(f"Potential Ascii encoding error in {values['name']}:{field.name} - {str(e)}")
        except Exception as e:
            print(f"Unknown encoding error in {values['name']}:{field.name} - {str(e)}")
        
        
        if bool(re.search(r"[^\\]\n", v)):
                raise ValueError(f"Unexpected newline(s) in {values['name']}:{field.name}.  Newline characters MUST be prefixed with \\")
        return v
    
    
    @validator("name", "author", 'description')
    def description_valid(cls, v, values, field):
        
        return SecurityContentObject_Abstract.free_text_field_valid(cls,v,values,field)
    

    @staticmethod
    def get_objects_by_name(names_to_find:set[str], objects_to_search:list[SecurityContentObject_Abstract])->Tuple[list[SecurityContentObject_Abstract], set[str]]:
        found_objects = list(filter(lambda obj: obj.name in names_to_find, objects_to_search))
        found_names = set([obj.name for obj in found_objects])
        missing_names = names_to_find - found_names
        return found_objects,missing_names
    
    @staticmethod
    def create_filename_to_content_dict(all_objects:list[SecurityContentObject_Abstract])->dict[str,SecurityContentObject_Abstract]:
        name_dict:dict[str,SecurityContentObject_Abstract] = dict()
        
        for object in all_objects:
            name_dict[str(pathlib.Path(object.file_path))] = object
        
        return name_dict
    
    