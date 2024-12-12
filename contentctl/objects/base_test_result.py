from typing import Union, Any
from enum import StrEnum

from pydantic import ConfigDict, BaseModel
from splunklib.data import Record                                                                   # type: ignore

from contentctl.helper.utils import Utils


# TODO (#267): Align test reporting more closely w/ status enums (as it relates to "untested")
# TODO (PEX-432): add status "UNSET" so that we can make sure the result is always of this enum
#   type; remove mypy ignores associated w/ these typing issues once we do
class TestResultStatus(StrEnum):
    """Enum for test status (e.g. pass/fail)"""
    # Test failed (detection did NOT fire appropriately)
    FAIL = "fail"

    # Test passed (detection fired appropriately)
    PASS = "pass"

    # Test skipped (nothing testable at present)
    SKIP = "skip"

    # Error/exception encountered during testing (e.g. network error); considered a failure as well
    # for the purpose aggregate metric gathering
    ERROR = "error"

    def __str__(self) -> str:
        return self.value


# TODO (#225): add validator to BaseTestResult which makes a lack of exception incompatible
#   with status ERROR
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

    # The duration of the test in seconds
    duration: float = 0

    # The search job metadata
    job_content: Union[Record, None] = None

    # The Splunk endpoint URL
    sid_link: Union[None, str] = None

    # Needed to allow for embedding of Exceptions in the model
    model_config = ConfigDict(
        validate_assignment=True,
        arbitrary_types_allowed=True
    )

    @property
    def passed(self) -> bool:
        """
        Property returning True if status is PASS; False otherwise (SKIP, FAIL, ERROR).
        :returns: bool indicating success/failure
        """
        return self.status == TestResultStatus.PASS

    @property
    def success(self) -> bool:
        """
        Property returning True if status is PASS or SKIP; False otherwise (FAIL, ERROR).
        :returns: bool indicating success/failure
        """
        return self.status in [TestResultStatus.PASS, TestResultStatus.SKIP]

    @property
    def failed(self) -> bool:
        """
        Property returning True if status is FAIL or ERROR; False otherwise (PASS, SKIP)
        :returns: bool indicating fialure if True
        """
        return self.status == TestResultStatus.FAIL or self.status == TestResultStatus.ERROR

    @property
    def complete(self) -> bool:
        """
        Property returning True when a test is complete (i.e. the result has been given a status)
        :returns: bool indicating the test is complete (has a status) if True
        """
        return self.status is not None

    def get_summary_dict(
        self,
        model_fields: list[str] = [
            "success", "exception", "message", "sid_link", "status", "duration", "wait_duration"
        ],
        job_fields: list[str] = ["search", "resultCount", "runDuration"],
    ) -> dict[str, Any]:
        """
        Aggregates a dictionary summarizing the test result model
        :param model_fields: the fields of the test result to gather
        :param job_fields: the fields of the job content to gather
        :returns: a dict summary
        """
        # Init the summary dict
        summary_dict: dict[str, Any] = {}

        # Grab the fields required
        for field in model_fields:
            if getattr(self, field, None) is not None:
                # Exceptions and enums cannot be serialized, so convert to str
                if isinstance(getattr(self, field), Exception):
                    summary_dict[field] = str(getattr(self, field))
                elif isinstance(getattr(self, field), StrEnum):
                    summary_dict[field] = str(getattr(self, field))
                else:
                    summary_dict[field] = getattr(self, field)
            else:
                # If field can't be found, set it to None (useful as unit and integration tests have
                # small differences in the number of fields they share)
                summary_dict[field] = None

        # Grab the job content fields required
        for field in job_fields:
            if self.job_content is not None:
                value: Any = self.job_content.get(field, None)                                      # type: ignore

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
