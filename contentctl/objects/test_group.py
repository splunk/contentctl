from pydantic import BaseModel

from contentctl.objects.unit_test import UnitTest
from contentctl.objects.integration_test import IntegrationTest
from contentctl.objects.unit_test_attack_data import UnitTestAttackData
from contentctl.objects.base_test_result import TestResultStatus


class TestGroup(BaseModel):
    """
    Groups of different types of tests relying on the same attack data
    :param name: Name of the TestGroup (typically derived from a unit test as 
        "{detection.name}:{test.name}")
    :param unit_test: a UnitTest
    :param integration_test: an IntegrationTest
    :param attack_data: the attack data associated with tests in the TestGroup
    """
    name: str
    unit_test: UnitTest
    integration_test: IntegrationTest
    attack_data: list[UnitTestAttackData]

    @classmethod
    def derive_from_unit_test(cls, unit_test: UnitTest, name_prefix: str) -> "TestGroup":
        """
        Given a UnitTest and a prefix, construct a TestGroup, with in IntegrationTest corresponding to the UnitTest
        :param unit_test: the UnitTest
        :param name_prefix: the prefix to be used for the TestGroup name (typically the Detection name)
        :returns: TestGroup
        """
        # construct the IntegrationTest
        integration_test = IntegrationTest.derive_from_unit_test(unit_test)

        # contruct and return the TestGroup
        return cls(
            name=f"{name_prefix}:{unit_test.name}",
            unit_test=unit_test,
            integration_test=integration_test,
            attack_data=unit_test.attack_data
        )

    def unit_test_skipped(self) -> bool:
        """
        Returns true if the unit test has been skipped
        :returns: bool
        """
        # Return True if skipped
        if self.unit_test.result is not None:
            return self.unit_test.result.status == TestResultStatus.SKIP

        # If no result yet, it has not been skipped
        return False

    def integration_test_skipped(self) -> bool:
        """
        Returns true if the integration test has been skipped
        :returns: bool
        """
        # Return True if skipped
        if self.integration_test.result is not None:
            return self.integration_test.result.status == TestResultStatus.SKIP

        # If no result yet, it has not been skipped
        return False

    def all_tests_skipped(self) -> bool:
        """
        Returns true if both the unit test and integration test have been skipped
        :returns: bool
        """
        return self.unit_test_skipped() and self.integration_test_skipped()
