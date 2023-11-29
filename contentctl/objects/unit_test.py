

from typing import Union, Optional
from pydantic import BaseModel, validator, ValidationError, Field

from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.unit_test_attack_data import UnitTestAttackData
from contentctl.objects.unit_test_result import UnitTestResult
from contentctl.objects.enums import SecurityContentType


class UnitTest(BaseModel):
    name: str = ...
    pass_condition: Optional[str] = None
    earliest_time: Optional[str] = None
    latest_time: Optional[str] = None
    baselines: list[UnitTestBaseline] = []
    attack_data: list[UnitTestAttackData] = Field(..., gt=0)
    result: Optional[UnitTestResult] = None

    