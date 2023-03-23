from pydantic import BaseModel, validator, ValidationError


from contentctl.objects.unit_test_attack_data import UnitTestAttackData
from contentctl.objects.unit_test_baseline import UnitTestBaseline
from contentctl.objects.unit_test_result import UnitTestResult
from typing import Union


class UnitTestTest(BaseModel):
    name: str
    file: str
    pass_condition: Union[str, None] = None
    earliest_time: Union[str, None] = None
    latest_time: Union[str, None] = None
    baselines: list[UnitTestBaseline] = []
    attack_data: list[UnitTestAttackData]
    result: Union[None, UnitTestResult]
