from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from contentctl.objects.security_content_object import SecurityContentObject
    from contentctl.objects.config import Config
    from contentctl.input.director import DirectorOutputDto

import re
import abc
import uuid
import datetime
from pydantic import BaseModel, field_validator, Field, ValidationInfo, FilePath, HttpUrl, NonNegativeInt, ConfigDict
from typing import Tuple, Optional, List
import pathlib





NO_FILE_NAME = "NO_FILE_NAME"
class SecurityContentObject_Abstract(BaseModel, abc.ABC):
    model_config = ConfigDict(use_enum_values=True,validate_default=True)
    # name: str = ...
    # author: str = Field(...,max_length=255)
    # date: datetime.date = Field(...)
    # version: NonNegativeInt = ...
    # id: uuid.UUID = Field(default_factory=uuid.uuid4) #we set a default here until all content has a uuid
    # description: str = Field(...,max_length=1000)
    # file_path: FilePath = Field(...)
    # references: Optional[List[HttpUrl]] = None
    
    name: str = Field("NO_NAME")
    author: str = Field("me",max_length=255)
    date: datetime.date = Field(datetime.date.today())
    version: NonNegativeInt = 1
    id: uuid.UUID = Field(default_factory=uuid.uuid4) #we set a default here until all content has a uuid
    description: str = Field("wow",max_length=10000)
    file_path: FilePath = Field("/tmp/doesnt_exist.yml")
    references: Optional[List[HttpUrl]] = None


    @staticmethod
    def objectListToNameList(objects:list[SecurityContentObject], config:Optional[Config]=None)->list[str]:
        return [object.getName(config) for object in objects]

    # This function is overloadable by specific types if they want to redefine names, for example
    # to have the format ESCU - NAME - Rule (config.tag - self.name - Rule)
    def getName(self, config:Optional[Config])->str:
        return self.name

    @field_validator('file_path')
    @classmethod
    def file_path_valid(cls, v: pathlib.PosixPath, info: ValidationInfo):
        if not v.name.endswith(".yml"):
            raise ValueError(f"All Security Content Objects must be YML files and end in .yml.  The following file does not: '{v}'")
        return v

    # @field_validator('date', mode='before')
    # @classmethod
    # def date_valid(cls, v: str, info: ValidationInfo):
    #     try:
    #         datetime.datetime.strptime(v, "%Y-%m-%d")
    #     except Exception as e:
    #         print(e)
    #         raise ValueError(f"date is not in ISO format YYYY-MM-DD: '{v}'")
    #     return v

    @field_validator('name','author','description')
    @classmethod
    def free_text_field_valid(cls, v: str, info:ValidationInfo)->str:
        try:
            v.encode('ascii')
        except UnicodeEncodeError as e:
            print(f"Potential Ascii encoding error in {info.field_name}:'{v}' - {str(e)}")
        except Exception as e:
            print(f"Unknown encoding error in {info.field_name}:'{v}' - {str(e)}")
        
        
        if bool(re.search(r"[^\\]\n", v)):
                raise ValueError(f"Unexpected newline(s) in {info.field_name}:'{v}'.  Newline characters MUST be prefixed with \\")
        return v
    
    @classmethod
    def mapNamesToSecurityContentObjects(cls, v: list[str], info:ValidationInfo)->list[SecurityContentObject]:
        director: Optional[DirectorOutputDto] = info.context.get("output_dto",None)
        if director is not None:
            name_map = director.name_to_content_map
        else:
            name_map = {}
        


        mappedObjects: list[SecurityContentObject] = []
        missing_objects: list[str] = []
        for object_name in v:
            found_object = name_map.get(object_name,None)
            if not found_object:
                missing_objects.append(object_name)
            else:
                mappedObjects.append(found_object)
        
        if len(missing_objects) > 0:
            raise ValueError(f"Failed to find the following objects: {missing_objects}")

        return mappedObjects


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
    

    
    