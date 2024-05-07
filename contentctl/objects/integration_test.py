from typing import Union

from pydantic import Field

from contentctl.objects.base_test import BaseTest, TestType
from contentctl.objects.unit_test import UnitTest
from contentctl.objects.integration_test_result import IntegrationTestResult
from contentctl.objects.base_test_result import TestResultStatus


class IntegrationTest(BaseTest):
    """
    An integration test for a detection against ES
    """
    # The test type (integration)
    test_type: TestType = Field(TestType.INTEGRATION)

    # The test result
    result: Union[None, IntegrationTestResult] = None

    @classmethod
    def derive_from_unit_test(cls, unit_test: UnitTest) -> "IntegrationTest":
        """
        Given a UnitTest, construct an IntegrationTest
        :param unit_test: the UnitTest
        :returns: IntegrationTest
        """
        return cls(
            name=unit_test.name,
            earliest_time=unit_test.earliest_time,
            latest_time=unit_test.latest_time,
        )

    def skip(self, message: str) -> None:
        """
        Skip the test by setting its result status
        :param message: the reason for skipping
        """
        self.result = IntegrationTestResult(
            message=message,
            status=TestResultStatus.SKIP
        )
