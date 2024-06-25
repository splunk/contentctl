from __future__ import annotations
from pydantic import BaseModel


from contentctl.objects.unit_test_ssa import UnitTestSSA


class UnitTestOld(BaseModel):
    name: str
    tests: list[UnitTestSSA]