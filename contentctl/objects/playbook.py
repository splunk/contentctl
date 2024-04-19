from __future__ import annotations
from typing import TYPE_CHECKING,Self
from pydantic import model_validator, Field, FilePath


from contentctl.objects.playbook_tags import PlaybookTag
from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.enums import PlaybookType


class Playbook(SecurityContentObject):
    type: PlaybookType = Field(...)
    
    # Override the type definition for filePath.
    # This MUST be backed by a file and cannot be None
    file_path: FilePath
    
    how_to_implement: str = Field(min_length=4)
    playbook: str = Field(min_length=4)
    app_list: list[str] = Field(...,min_length=0) 
    tags: PlaybookTag = Field(...)
    

    
    @model_validator(mode="after")
    def ensureJsonAndPyFilesExist(self)->Self:
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
    def ensureFileNameMatchesSearchName(self)->Self:
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

    