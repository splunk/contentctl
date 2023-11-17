from typing import Union
from enum import Enum

from pydantic import BaseModel
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
    message: Union[None, str] = None
    exception: Union[Exception, None] = None
    success: bool = False
    duration: float = 0
    job_content: Union[Record, None] = None
    status: Union[TestResultStatus, None] = None

    class Config:
        validate_assignment = True
        arbitrary_types_allowed = True

    def get_summary_dict(
        self,
        model_fields: list[str] = [
            "success", "exception", "message", "sid_link", "status", "duration"
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
            if getattr(self, field) is not None:
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
