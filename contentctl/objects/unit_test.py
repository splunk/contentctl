

from pydantic import BaseModel, validator, ValidationError

from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.unit_test_test import UnitTestTest
from contentctl.objects.unit_test_baseline import UnitTestBaseline
from contentctl.objects.unit_test_attack_data import UnitTestAttackData

class UnitTest(BaseModel, SecurityContentObject):
    name: str
    baselines: list[UnitTestBaseline] = None
    attack_data: list[UnitTestAttackData]
    