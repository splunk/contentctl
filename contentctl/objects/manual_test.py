from __future__ import annotations

from pydantic import Field

from contentctl.objects.test_attack_data import TestAttackData
from contentctl.objects.manual_test_result import ManualTestResult
from contentctl.objects.base_test import BaseTest, TestType
from contentctl.objects.base_test_result import TestResultStatus


class ManualTest(BaseTest):
    """
    A manual test for a detection
    """
    # The test type (manual)
    test_type: TestType = Field(default=TestType.MANUAL)

    # The attack data to be ingested for the manual test
    attack_data: list[TestAttackData]

    # The result of the manual test
    result: ManualTestResult | None = None

    def skip(self, message: str) -> None:
        """
        Skip the test by setting its result status
        :param message: the reason for skipping
        """
        self.result = ManualTestResult(                                                             # type: ignore
            message=message,
            status=TestResultStatus.SKIP
        )
