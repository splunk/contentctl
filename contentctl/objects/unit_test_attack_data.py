from __future__ import annotations
from pydantic import BaseModel, HttpUrl, FilePath, Field,ConfigDict
from typing import Union, Optional


class UnitTestAttackData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    data: Union[HttpUrl, FilePath] = Field(...)
    # TODO - should source and sourcetype should be mapped to a list
    # of supported source and sourcetypes in a given environment?
    source: str = Field(...)
    sourcetype: str = Field(...)
    custom_index: Optional[str] = None
    host: Optional[str] = None