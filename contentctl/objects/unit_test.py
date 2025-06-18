from __future__ import annotations

from typing import Any

from pydantic import Field, model_serializer

from contentctl.objects.base_test import BaseTest, TestType
from contentctl.objects.base_test_result import TestResultStatus
from contentctl.objects.test_attack_data import TestAttackData
from contentctl.objects.unit_test_result import UnitTestResult


class UnitTest(BaseTest):
    """
    A unit test for a detection
    """

    # contentType: SecurityContentType = SecurityContentType.unit_tests

    # The test type (unit)
    test_type: TestType = Field(default=TestType.UNIT)

    # The attack data to be ingested for the unit test
    attack_data: list[TestAttackData]

    # The result of the unit test
    result: UnitTestResult | None = None

    def skip(self, message: str) -> None:
        """
        Skip the test by setting its result status
        :param message: the reason for skipping
        """
        self.result = UnitTestResult(  # type: ignore
            message=message, status=TestResultStatus.SKIP
        )

    @model_serializer
    def serialize_model(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "test_type": self.test_type.value,
            "attack_data": [
                attack_data.model_dump() for attack_data in self.attack_data
            ],
        }
