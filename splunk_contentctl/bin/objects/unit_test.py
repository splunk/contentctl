
from pydantic import BaseModel, validator, ValidationError

from bin.objects.unit_test_attack_data import UnitTestAttackData
from bin.objects.unit_test_baseline import UnitTestBaseline

class UnitTest(BaseModel):
    name: str
    data_model: str
    data_source: str
    baselines: list[UnitTestBaseline] = None
    attack_data: list[UnitTestAttackData]
    