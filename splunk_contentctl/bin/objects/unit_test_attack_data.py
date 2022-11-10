

from pydantic import BaseModel, validator, ValidationError


class UnitTestAttackData(BaseModel):
    file_name: str
    data: str
    source: str
    sourcetype: str
    update_timestamp: bool = False