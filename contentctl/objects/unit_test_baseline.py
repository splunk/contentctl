from pydantic import BaseModel, ConfigDict
from typing import Union


class UnitTestBaseline(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    file: str
    pass_condition: str
    earliest_time: Union[str, None] = None
    latest_time: Union[str, None] = None
