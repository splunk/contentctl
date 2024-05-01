from __future__ import annotations
from typing import Optional
from pydantic import BaseModel, Field
from pydantic import Field


class UnitTestAttackDataSSA(BaseModel):
    file_name:Optional[str] = None
    data: str = Field(...)
    # TODO - should source and sourcetype should be mapped to a list
    # of supported source and sourcetypes in a given environment?
    source: str = Field(...)

    sourcetype: Optional[str] = None


class UnitTestSSA(BaseModel):
    """
    A unit test for a detection
    """
    name: str

    # The attack data to be ingested for the unit test
    attack_data: list[UnitTestAttackDataSSA] = Field(...)





    

