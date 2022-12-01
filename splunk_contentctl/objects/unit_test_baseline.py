

from pydantic import BaseModel, validator, ValidationError
from typing import Union

class UnitTestBaseline(BaseModel):
    name: str
    file: str
    pass_condition: str
    earliest_time: Union[str,None] = None
    latest_time: Union[str,None] = None