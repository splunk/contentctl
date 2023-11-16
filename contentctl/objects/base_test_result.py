from pydantic import BaseModel

from typing import Union


class BaseTestResult(BaseModel):
    message: Union[None, str] = None
    exception: Union[Exception, None] = None
    success: bool = False
    duration: float = 0

    class Config:
        validate_assignment = True
        arbitrary_types_allowed = True
