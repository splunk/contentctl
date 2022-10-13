

from pydantic import BaseModel, validator, ValidationError


class UnitTestAttackData(BaseModel):
    data: str
    source: str = None
    sourcetype: str = None