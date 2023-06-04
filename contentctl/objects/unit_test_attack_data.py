from pydantic import BaseModel, validator, ValidationError
from contentctl.helper.utils import Utils
from typing import Union


class UnitTestAttackData(BaseModel):
    data: str = None
    source: str = None
    sourcetype: str = None
    update_timestamp: bool = None
    custom_index: str = None
    host: str = None

    @validator("data", always=True)
    def validate_data(cls, v, values):
        return v
        try:
            Utils.verify_file_exists(v)
        except Exception as e:
            raise (ValueError(f"Cannot find file {v}: {str(e)}"))
        return v
