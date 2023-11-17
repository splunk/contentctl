from typing import Union
from pydantic import validator

from contentctl.objects.abstract_security_content_objects.detection_abstract import Detection_Abstract
from contentctl.objects.test_group import TestGroup


class Detection(Detection_Abstract):
    # Customization to the Detection Class go here.
    # You may add fields and/or validations

    # You may also experiment with removing fields
    # and/or validations,  or chagning validation(s).
    # Please be aware that many defaults field(s)
    # or validation(s) are required and removing or
    # them or modifying their behavior may cause
    # undefined issues with the contentctl tooling
    # or output of the tooling.

    # A list of groups of tests, relying on the same data
    test_groups: Union[list[TestGroup], None] = None

    @validator("test_groups", always=True)
    def validate_test_groups(cls, value, values) -> Union[list[TestGroup], None]:
        """
        Validates the `test_groups` field and constructs the model from the list of unit tests
        if no explicit construct was provided
        :param value: the value of the field `test_groups`
        :param values: a dict of the other fields in the Detection model
        """
        # if the value was not the None default, do nothing
        if value is not None:
            return value

        # iterate over the unit tests and create a TestGroup (and as a result, an IntegrationTest) for each
        test_groups: list[TestGroup] = []
        for unit_test in values["tests"]:
            test_group = TestGroup.derive_from_unit_test(unit_test, values["name"])
            test_groups.append(test_group)

        # now add each integration test to the list of tests
        for test_group in test_groups:
            values["tests"].append(test_group.integration_test)
        return test_groups
