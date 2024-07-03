from __future__ import annotations

from typing import Union,TYPE_CHECKING
from splunklib.data import Record
from contentctl.objects.base_test_result import BaseTestResult, TestResultStatus

if TYPE_CHECKING:
    from contentctl.objects.config import Infrastructure

FORCE_TEST_FAILURE_FOR_MISSING_OBSERVABLE = False

NO_SID = "Testing Failed, NO Search ID"
SID_TEMPLATE = "{server}:{web_port}/en-US/app/search/search?sid={sid}"


class UnitTestResult(BaseTestResult):
    missing_observables: list[str] = []
    
    def set_job_content(
        self,
        content: Union[Record, None],
        config: Infrastructure,
        status: TestResultStatus,
        exception: Union[Exception, None] = None,
        duration: float = 0,
    ) -> bool:
        """
        Sets various fields in the result, pulling some fields from the provided search job's
        content
        :param content: search job content
        :param config: the Infrastructure config
        :param status: the test status (TestResultStatus)
        :param exception: an Exception raised during the test (may be None)
        :param duration: the overall duration of the test, including data replay and cleanup time
            (float, in seconds)
        :returns: bool indicating test success (inclusive of PASS and SKIP)
        """
        # Set duration, exception and status
        self.duration = round(duration, 2)
        self.exception = exception
        self.status = status
        self.job_content = content
        
        # Set the job content, if given
        if content is not None:
            if self.status == TestResultStatus.PASS:
                self.message = "TEST PASSED"
            elif self.status == TestResultStatus.FAIL:
                self.message = "TEST FAILED"
            elif self.status == TestResultStatus.ERROR:
                self.message = "TEST ERROR"
            elif self.status == TestResultStatus.SKIP:
                #A test that was SKIPPED should not have job content since it should not have been run.
                self.message = "TEST SKIPPED"

            if not config.instance_address.startswith("http://"):
                sid_template = f"http://{SID_TEMPLATE}"
            else:
                sid_template = SID_TEMPLATE
            self.sid_link = sid_template.format(
                server=config.instance_address,
                web_port=config.web_ui_port,
                sid=content.get("sid", None),
            )

        elif self.status == TestResultStatus.SKIP:
            self.message = "TEST SKIPPED" 
            pass

        elif content is None:
            self.status = TestResultStatus.ERROR
            if self.exception is not None:
                self.message = f"EXCEPTION: {str(self.exception)}"
            else:
                self.message = f"ERROR with no more specific message available."
            self.sid_link = NO_SID

        return self.success
