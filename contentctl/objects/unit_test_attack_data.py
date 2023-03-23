from pydantic import BaseModel, validator, ValidationError
from contentctl.helper.utils import Utils
from typing import Union


class UnitTestAttackData(BaseModel):
    file_name: str
    data: str
    source: str
    sourcetype: str
    update_timestamp: bool = False
    custom_index: Union[str, None] = None
    host: Union[str, None] = None

    @validator("data", always=True)
    def validate_data(cls, v, values):
        return v
        try:
            Utils.verify_file_exists(v)
        except Exception as e:
            raise (ValueError(f"Cannot find file {v}: {str(e)}"))
        return v
