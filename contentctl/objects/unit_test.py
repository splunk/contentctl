

from typing import Union

from pydantic import Field

# from contentctl.objects.security_content_object import SecurityContentObject
# from contentctl.objects.enums import SecurityContentType
from contentctl.objects.unit_test_baseline import UnitTestBaseline
from contentctl.objects.unit_test_attack_data import UnitTestAttackData
from contentctl.objects.unit_test_result import UnitTestResult
from contentctl.objects.base_test import BaseTest, TestType


class UnitTest(BaseTest):
    """
    A unit test for a detection
    """
    # contentType: SecurityContentType = SecurityContentType.unit_tests

    # The test type (unit)
    test_type: TestType = Field(TestType.UNIT, const=True)

    # The condition to check if the searh was successful
    pass_condition: Union[str, None] = None

    # Baselines to be run before a unit test
    baselines: list[UnitTestBaseline] = []

    # The attack data to be ingested for the unit test
    attack_data: list[UnitTestAttackData]

    # The result of the unit test
    result: Union[None, UnitTestResult] = None
