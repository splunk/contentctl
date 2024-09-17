from contentctl.objects.base_test_result import BaseTestResult


class IntegrationTestResult(BaseTestResult):
    """
    An integration test result
    """
    # the total time we slept waiting for the detection to fire after activating it
    wait_duration: int | None = None
