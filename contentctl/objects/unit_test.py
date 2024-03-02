from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from contentctl.objects.unit_test_attack_data import UnitTestAttackData
    from contentctl.objects.unit_test_result import UnitTestResult

from contentctl.objects.unit_test_attack_data import UnitTestAttackData
from contentctl.objects.unit_test_result import UnitTestResult

class UnitTest(BaseModel):
    name: str = Field(...)
    pass_condition: Optional[str] = None
    earliest_time: Optional[str] = None
    latest_time: Optional[str] = None
    attack_data: list[UnitTestAttackData] = Field(..., min_length=1)
    result: Optional[UnitTestResult] = None

    