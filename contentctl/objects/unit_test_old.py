from __future__ import annotations
from pydantic import BaseModel, ConfigDict


from contentctl.objects.unit_test_ssa import UnitTestSSA


class UnitTestOld(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    tests: list[UnitTestSSA]