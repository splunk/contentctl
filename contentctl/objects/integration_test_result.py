from typing import Optional
from contentctl.objects.base_test_result import BaseTestResult


SAVED_SEARCH_TEMPLATE = "{server}:{web_port}/en-US/{path}"


class IntegrationTestResult(BaseTestResult):
    """
    An integration test result
    """
    # the total time we slept waiting for the detection to fire after activating it
    wait_duration: Optional[int] = None
