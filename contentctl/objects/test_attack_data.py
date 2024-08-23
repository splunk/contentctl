from __future__ import annotations
from pydantic import BaseModel, HttpUrl, FilePath, Field


class TestAttackData(BaseModel):
    data: HttpUrl | FilePath = Field(...)
    # TODO - should source and sourcetype should be mapped to a list
    # of supported source and sourcetypes in a given environment?
    source: str = Field(...)
    sourcetype: str = Field(...)
    custom_index: str | None = None
    host: str | None = None
