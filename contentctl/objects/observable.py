from pydantic import BaseModel, field_validator
from contentctl.objects.constants import SES_OBSERVABLE_TYPE_MAPPING, RBA_OBSERVABLE_ROLE_MAPPING


class Observable(BaseModel):
    name: str
    type: str
    role: list[str]

    @field_validator('name')
    def check_name(cls, v: str):
        if v == "":
            raise ValueError("No name provided for observable")
        return v

    @field_validator('type')
    def check_type(cls, v: str):
        if v not in SES_OBSERVABLE_TYPE_MAPPING.keys():
            raise ValueError(
                f"Invalid type '{v}' provided for observable.  Valid observable types are "
                f"{SES_OBSERVABLE_TYPE_MAPPING.keys()}"
            )
        return v

    @field_validator('role')
    def check_roles(cls, v: list[str]):
        if len(v) == 0:
            raise ValueError("Error, at least 1 role must be listed for Observable.")
        if len(v) > 1:
            raise ValueError("Error, each Observable can only have one role.")
        for role in v:
            if role not in RBA_OBSERVABLE_ROLE_MAPPING.keys():
                raise ValueError(
                    f"Invalid role '{role}' provided for observable.  Valid observable types are "
                    f"{RBA_OBSERVABLE_ROLE_MAPPING.keys()}"
                )
        return v
