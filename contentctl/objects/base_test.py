from enum import Enum
from typing import Union

from pydantic import BaseModel

from contentctl.objects.base_test_result import BaseTestResult


class TestType(str, Enum):
    """
    Types of tests
    """
    UNIT = "unit"
    INTEGRATION = "integration"


class BaseTest(BaseModel):
    """
    A test case for a detection
    """
    # Test name
    name: str

    # The test type
    test_type: TestType

    # Search window start time
    earliest_time: Union[str, None] = None

    # Search window end time
    latest_time: Union[str, None] = None

    # The test result
    result: Union[None, BaseTestResult] = None
