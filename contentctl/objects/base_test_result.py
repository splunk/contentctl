from typing import Union
from enum import Enum

from pydantic import BaseModel, validator
from splunklib.data import Record

from contentctl.helper.utils import Utils


class TestResultStatus(str, Enum):
    """Enum for test status (e.g. pass/fail)"""
    # Test failed (detection did NOT fire appropriately)
    FAIL = "fail"

    # Test passed (detection fired appropriately)
    PASS = "pass"

    # Test skipped (nothing testable at present)
    SKIP = "skip"

    # Error/exception encountered during testing (e.g. network error)
    ERROR = "error"

    def __str__(self) -> str:
        return self.value


class BaseTestResult(BaseModel):
    """
    Base class for test results
    """
    # Message for the result
    message: Union[None, str] = None

    # Any exception that was raised (may be None)
    exception: Union[Exception, None] = None

    # The status (PASS, FAIL, SKIP, ERROR)
    status: Union[TestResultStatus, None] = None

    # Whether the test passed (should only be True when status==PASS)
    success: bool = False

    # The duration of the test in seconds
    duration: float = 0

    # The search job metadata
    job_content: Union[Record, None] = None

    # The Splunk endpoint URL
    sid_link: Union[None, str] = None

    class Config:
        validate_assignment = True

        # Needed to allow for embedding of Exceptions in the model
        arbitrary_types_allowed = True

    @validator("success", always=True)
    @classmethod
    def derive_success_from_status(cls, v, values) -> bool:
        """
        If a status is provided at initialization, we can derive success from it
        """
        # If a status is provided an initialization, derive success
        if ("status" in values) and (values["status"] is not None):
            # Success is True only if status is PASS
            if values["status"] == TestResultStatus.PASS:
                return True
            else:
                if v is not False:
                    raise ValueError(f"Status {values['status'].value} is not compatible with success={v}")
                return False
        return v

    @property
    def failed_and_complete(self) -> bool:
        """
        Uses status to determine if a test was a failure; useful because success == False for a SKIP, but it is also
        not a failure
        :returns: bool indicating the test failed and is complete (in that it has a status)
        """
        if self.status is not None:
            return self.status == TestResultStatus.FAIL or self.status == TestResultStatus.ERROR
        return False

    def get_summary_dict(
        self,
        model_fields: list[str] = [
            "success", "exception", "message", "sid_link", "status", "duration", "wait_duration"
        ],
        job_fields: list[str] = ["search", "resultCount", "runDuration"],
    ) -> dict:
        """
        Aggregates a dictionary summarizing the test result model
        :param model_fields: the fields of the test result to gather
        :param job_fields: the fields of the job content to gather
        :returns: a dict summary
        """
        # Init the summary dict
        summary_dict = {}

        # Grab the fields required
        for field in model_fields:
            if getattr(self, field, None) is not None:
                # Exceptions and enums cannot be serialized, so convert to str
                if isinstance(getattr(self, field), Exception):
                    summary_dict[field] = str(getattr(self, field))
                elif isinstance(getattr(self, field), Enum):
                    summary_dict[field] = str(getattr(self, field))
                else:
                    summary_dict[field] = getattr(self, field)

        # Grab the job content fields required
        for field in job_fields:
            if self.job_content is not None:
                value = self.job_content.get(field, None)

                # convert runDuration to a fixed width string representation of a float
                if field == "runDuration":
                    try:
                        value = Utils.getFixedWidth(float(value), 3)
                    except Exception:
                        value = Utils.getFixedWidth(0, 3)
                summary_dict[field] = value
            else:
                # If no job content, set all fields to None
                summary_dict[field] = None

        # Return the summary_dict
        return summary_dict
