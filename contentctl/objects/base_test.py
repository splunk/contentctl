from enum import Enum
from typing import Union
from abc import ABC, abstractmethod

from pydantic import BaseModel

from contentctl.objects.base_test_result import BaseTestResult


class TestType(str, Enum):
    """
    Types of tests
    """
    UNIT = "unit"
    INTEGRATION = "integration"

    def __str__(self) -> str:
        return self.value


# TODO (cmcginley): enforce distinct test names w/in detections
class BaseTest(BaseModel, ABC):
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

    @abstractmethod
    def skip(self, message: str) -> None:
        """
        Skip a test
        """
        raise NotImplementedError(
            "BaseTest test is an abstract class; skip must be implemented by subclasses"
        )
