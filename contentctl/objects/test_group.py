from typing import Self

from pydantic import BaseModel

from contentctl.objects.unit_test import UnitTest
from contentctl.objects.integration_test import IntegrationTest
from contentctl.objects.unit_test_attack_data import UnitTestAttackData


class TestGroup(BaseModel):
    """
    Groups of different types of tests relying on the same attack data
    """
    name: str
    unit_test: UnitTest
    integration_test: IntegrationTest
    attack_data: list[UnitTestAttackData]

    # TODO: how often do we actually encounter tests w/ an earliest/latest time defined?
    @classmethod
    def derive_from_unit_test(cls, unit_test: UnitTest, name_prefix: str) -> Self:
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
