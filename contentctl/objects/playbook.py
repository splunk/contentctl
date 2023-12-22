from __future__ import annotations

from pydantic import field_validator, model_validator, ValidationInfo, Field

from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.playbook_tags import PlaybookTag

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


    