from typing import Union

from splunklib.data import Record

from contentctl.objects.test_config import Infrastructure
from contentctl.objects.base_test_result import BaseTestResult, TestResultStatus

FORCE_TEST_FAILURE_FOR_MISSING_OBSERVABLE = False

NO_SID = "Testing Failed, NO Search ID"
SID_TEMPLATE = "{server}:{web_port}/en-US/app/search/search?sid={sid}"


class UnitTestResult(BaseTestResult):
    missing_observables: list[str] = []

    def set_job_content(
        self,
        content: Union[Record, None],
        config: Infrastructure,
        exception: Union[Exception, None] = None,
        success: bool = False,
        duration: float = 0,
    ):
        # Set duration, exception and success
        self.duration = round(duration, 2)
        self.exception = exception
        self.success = success

        # Set the job content, if given
        if content is not None:
            self.job_content = content

            if success:
                self.message = "TEST PASSED"
            else:
                self.message = "TEST FAILED"

            if not config.instance_address.startswith("http://"):
                sid_template = f"http://{SID_TEMPLATE}"
            else:
                sid_template = SID_TEMPLATE
            self.sid_link = sid_template.format(
                server=config.instance_address,
                web_port=config.web_ui_port,
                sid=content.get("sid", None),
            )

        # TODO: this error message seems not the most helpful, since content must be None for it to be set
        elif content is None:
            self.job_content = None
            self.success = False
            if self.exception is not None:
                self.message = f"EXCEPTION: {str(self.exception)}"
            self.sid_link = NO_SID

        # Set status if the test was not already skipped
        if self.status != TestResultStatus.SKIP:
            if self.exception is not None:
                self.status = TestResultStatus.ERROR
            elif not self.success:
                self.status = TestResultStatus.FAIL
            else:
                self.status = TestResultStatus.PASS

        return self.success
