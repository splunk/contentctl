from __future__ import annotations
import re
import abc
import uuid
import datetime
from pydantic import BaseModel, field_validator, Field, ValidationInfo, FilePath
from typing import Tuple

import uuid
import pathlib

NO_FILE_NAME = "NO_FILE_NAME"
class SecurityContentObject_Abstract(BaseModel, abc.ABC):
    name: str = Field(...,max_length=67)
    author: str = Field(...,max_length=255)
    date: datetime.date = Field(...)
    version: int = Field(...,ge=0)
    id: uuid.UUID = Field(default_factory=uuid.uuid4) #we set a default here until all content has a uuid
    description: str = Field(...,max_length=1000)
    file_path: FilePath = Field(...)

    
    @field_validator('file_path')
    @classmethod
    def file_path_valid(cls, v: str, info: ValidationInfo):
        if not v.endswith(".yml"):
            raise ValueError(f"All Security Content Objects must be YML files and end in .yml.  The following file does not: '{v}'")
        return v

    @field_validator('date', mode='before')
    @classmethod
    def date_valid(cls, v: str, info: ValidationInfo):
        try:
            datetime.datetime.strptime(v, "%Y-%m-%d")
        except:
            raise ValueError(f"date is not in ISO format YYYY-MM-DD: '{v}'")
        return v

    @field_validator('name','author','description')
    @classmethod
    def free_text_field_valid(cls, v: str, info:ValidationInfo):
        try:
            v.encode('ascii')
        except UnicodeEncodeError as e:
            print(f"Potential Ascii encoding error in {info.field_name}:'{v}' - {str(e)}")
        except Exception as e:
            print(f"Unknown encoding error in {info.field_name}:'{v}' - {str(e)}")
        
        
        if bool(re.search(r"[^\\]\n", v)):
                raise ValueError(f"Unexpected newline(s) in {info.field_name}:'{v}'.  Newline characters MUST be prefixed with \\")
        return v
    


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
    
    