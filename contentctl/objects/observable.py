from __future__ import annotations
from pydantic import BaseModel, validator

from contentctl.objects.constants import *



class Observable(BaseModel):
    name: str
    type: str
    role: list[str]



    @validator('name')
    def check_name(cls, v, values):
        if v == "":
            raise ValueError("No name provided for observable")
        return v
    
    @validator('type')
    def check_type(cls, v, values):
        if v not in SES_OBSERVABLE_TYPE_MAPPING.keys():
            raise ValueError(f"Invalid type '{v}' provided for observable.  Valid observable types are {SES_OBSERVABLE_TYPE_MAPPING.keys()}")
        return v

    
    @validator('role', each_item=False)
    def check_roles_not_empty(cls, v, values):
        if len(v) == 0:
            raise ValueError("At least one role must be defined for observable")
        return v

    @validator('role', each_item=True)
    def check_roles(cls, v, values):
        if v not in SES_OBSERVABLE_ROLE_MAPPING.keys():
            raise ValueError(f"Invalid role '{v}' provided for observable.  Valid observable types are {SES_OBSERVABLE_ROLE_MAPPING.keys()}")
        return v


    