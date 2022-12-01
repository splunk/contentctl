

from pydantic import BaseModel, validator, ValidationError

DEFAULT_INDEX = "main"
class UnitTestAttackData(BaseModel):
    file_name: str
    data: str
    source: str
    sourcetype: str
    update_timestamp: bool = False
    custom_index:str = DEFAULT_INDEX