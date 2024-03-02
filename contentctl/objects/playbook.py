from __future__ import annotations
from typing import TYPE_CHECKING
from pydantic import field_validator, model_validator, ValidationInfo, Field, FilePath


from contentctl.objects.playbook_tags import PlaybookTag
from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.enums import PlaybookType


class Playbook(SecurityContentObject):
    type: PlaybookType = Field(...)
    how_to_implement: str = Field(min_length=4)
    playbook: str = Field(min_length=4)
    app_list: list[str] = Field(...,min_length=0) 
    tags: PlaybookTag = Field(...)


    @field_validator('how_to_implement')
    @classmethod
    def encode_error(cls, v:str, info:ValidationInfo):
        return super().free_text_field_valid(v,info)
    
    @model_validator(mode="after")
    def ensureJsonAndPyFilesExist(self)->Playbook:
        json_file_path = self.file_path.with_suffix(".json")
        python_file_path = self.file_path.with_suffix(".py")
        missing:list[str] = []
        if not json_file_path.is_file():
            missing.append(f"Playbook file named '{self.file_path.name}' MUST "\
                           f"have a .json file named '{json_file_path.name}', "\
                            "but it does not exist")
            
        if not python_file_path.is_file():
            missing.append(f"Playbook file named '{self.file_path.name}' MUST "\
                           f"have a .py file named '{python_file_path.name}', "\
                            "but it does not exist")
            
        
        if len(missing) == 0:
            return self
        else:
            missing_files_string = '\n - '.join(missing)
            raise ValueError(f"Playbook files missing:\n -{missing_files_string}")


    #Override playbook file name checking FOR NOW
    @model_validator(mode="after")
    def ensureFileNameMatchesSearchName(self):
        file_name = self.name \
            .replace(' ', '_') \
            .replace('-','_') \
            .replace('.','_') \
            .replace('/','_') \
            .lower() + ".yml"
        
        #allow different capitalization FOR NOW in playbook file names
        if (self.file_path is not None and file_name != self.file_path.name.lower()):
            raise ValueError(f"The file name MUST be based off the content 'name' field:\n"\
                            f"\t- Expected File Name: {file_name}\n"\
                            f"\t- Actual File Name  : {self.file_path.name}")

        return self

    