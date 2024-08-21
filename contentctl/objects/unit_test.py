from __future__ import annotations

from pydantic import Field

from contentctl.objects.unit_test_baseline import UnitTestBaseline
from contentctl.objects.test_attack_data import TestAttackData
from contentctl.objects.unit_test_result import UnitTestResult
from contentctl.objects.base_test import BaseTest, TestType
from contentctl.objects.base_test_result import TestResultStatus


class UnitTest(BaseTest):
    """
    A unit test for a detection
    """
    # contentType: SecurityContentType = SecurityContentType.unit_tests

    # The test type (unit)
    test_type: TestType = Field(default=TestType.UNIT)

    # TODO (cmcginley): looks like pass_condition has gone the way of the dodo; can I remove?
    # The condition to check if the search was successful
    pass_condition: str | None = None

    # TODO (cmcginley): looks like baselines has gone the way of the dodo; can I remove?
    # Baselines to be run before a unit test
    baselines: list[UnitTestBaseline] = []

    # The attack data to be ingested for the unit test
    attack_data: list[TestAttackData]

    # The result of the unit test
    result: UnitTestResult | None = None

    def skip(self, message: str) -> None:
        """
        Skip the test by setting its result status
        :param message: the reason for skipping
        """
        self.result = UnitTestResult(                                                               # type: ignore
            message=message,
            status=TestResultStatus.SKIP
        )
