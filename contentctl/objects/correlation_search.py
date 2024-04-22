import logging
import time
from typing import Union, Optional, Any
from enum import Enum

from pydantic import BaseModel, validator, Field
from splunklib.results import JSONResultsReader, Message                                            # type: ignore
from splunklib.binding import HTTPError, ResponseReader                                             # type: ignore
import splunklib.client as splunklib                                                                # type: ignore
from tqdm import tqdm                                                                               # type: ignore

from contentctl.objects.risk_analysis_action import RiskAnalysisAction
from contentctl.objects.notable_action import NotableAction
from contentctl.objects.base_test_result import TestResultStatus
from contentctl.objects.integration_test_result import IntegrationTestResult
from contentctl.actions.detection_testing.progress_bar import (
    format_pbar_string,
    TestReportingType,
    TestingStates
)


# Suppress logging by default; enable for local testing
ENABLE_LOGGING = False
LOG_LEVEL = logging.DEBUG
LOG_PATH = "correlation_search.log"


def get_logger() -> logging.Logger:
    """
    Gets a logger instance for the module; logger is configured if not already configured. The
    NullHandler is used to suppress loggging when running in production so as not to conflict w/
    contentctl's larger pbar-based logging. The StreamHandler is enabled by setting ENABLE_LOGGING
    to True (useful for debugging/testing locally)
    """
    # get logger for module
    logger = logging.getLogger(__name__)

    # set propagate to False if not already set as such (needed to that we do not flow up to any
    # root loggers)
    if logger.propagate:
        logger.propagate = False

    # if logger has no handlers, it needs to be configured for the first time
    if not logger.hasHandlers():
        # set level
        logger.setLevel(LOG_LEVEL)

        # if logging enabled, use a StreamHandler; else, use the NullHandler to suppress logging
        handler: logging.Handler
        if ENABLE_LOGGING:
            handler = logging.FileHandler(LOG_PATH)
        else:
            handler = logging.NullHandler()

        # Format our output
        formatter = logging.Formatter('%(asctime)s - %(levelname)s:%(name)s - %(message)s')
        handler.setFormatter(formatter)

        # Set handler level and add to logger
        handler.setLevel(LOG_LEVEL)
        logger.addHandler(handler)

    return logger


class IntegrationTestingError(Exception):
    """Base exception class for integration testing"""
    pass


class ServerError(IntegrationTestingError):
    """An error encounterd during integration testing, as provided by the server (Splunk instance)"""
    pass


class ClientError(IntegrationTestingError):
    """An error encounterd during integration testing, on the client's side (locally)"""
    pass


class SavedSearchKeys(str, Enum):
    """
    Various keys into the SavedSearch content
    """
    # setup the names of the keys we expect to access in content
    EARLIEST_TIME_KEY = "dispatch.earliest_time"
    LATEST_TIME_KEY = "dispatch.latest_time"
    CRON_SCHEDULE_KEY = "cron_schedule"
    RISK_ACTION_KEY = "action.risk"
    NOTABLE_ACTION_KEY = "action.notable"
    DISBALED_KEY = "disabled"


class Indexes(str, Enum):
    """
    Indexes we search against
    """
    # setup the names of the risk and notable indexes
    RISK_INDEX = "risk"
    NOTABLE_INDEX = "notable"


class TimeoutConfig(int, Enum):
    """
    Configuration values for the exponential backoff timer
    """
    # base amount to sleep for before beginning exponential backoff during testing
    BASE_SLEEP = 60

    # max amount to wait before timing out during exponential backoff
    MAX_SLEEP = 210


# TODO (cmcginley): evaluate sane defaults for timeframe for integration testing (e.g. 5y is good
#   now, but maybe not always...); maybe set latest/earliest to None?
class ScheduleConfig(str, Enum):
    """
    Configuraton values for the saved search schedule
    """
    EARLIEST_TIME: str = "-5y@y"
    LATEST_TIME: str = "-1m@m"
    CRON_SCHEDULE: str = "*/1 * * * *"


class ResultIterator:
    """An iterator wrapping the results abstractions provided by Splunk SDK

    Given a ResponseReader, constructs a JSONResultsReader and iterates over it; when Message instances are encountered,
    they are logged if the message is anything other than "error", in which case an error is raised. Regular results are
    returned as expected
    :param response_reader: a ResponseReader object
    :param logger: a Logger object
    """
    def __init__(self, response_reader: ResponseReader) -> None:
        # init the results reader
        self.results_reader: JSONResultsReader = JSONResultsReader(
            response_reader
        )

        # get logger
        self.logger: logging.Logger = get_logger()

    def __iter__(self) -> "ResultIterator":
        return self

    def __next__(self) -> dict:
        # Use a reader for JSON format so we can iterate over our results
        for result in self.results_reader:
            # log messages, or raise if error
            if isinstance(result, Message):
                # convert level string to level int
                level_name = result.type.strip().upper()
                level: int = logging.getLevelName(level_name)

                # log message at appropriate level and raise if needed
                message = f"{result.type}: {result.message}"
                self.logger.log(level, message)
                if level == logging.ERROR:
                    raise ServerError(message)

            # if dict, just return
            elif isinstance(result, dict):
                return result

            # raise for any unexpected types
            else:
                raise ClientError("Unexpected result type")

        # stop iteration if we run out of things to iterate over internally
        raise StopIteration


class PbarData(BaseModel):
    """
    Simple model encapsulating a pbar instance and the data needed for logging to it
    :param pbar: a tqdm instance to use for logging
    :param fq_test_name: the fully qualifed (fq) test name ("<detection_name>:<test_name>") used for logging
    :param start_time: the start time used for logging
    """
    pbar: tqdm
    fq_test_name: str
    start_time: float

    class Config:
        # needed to support the tqdm type
        arbitrary_types_allowed = True


class CorrelationSearch(BaseModel):
    """Representation of a correlation search in Splunk

    In Enterprise Security, a correlation search is wrapper around the saved search entity. This search represents a
    detection rule for our purposes.
    :param detection_name: the name of the search/detection (e.g. "Windows Modify Registry EnableLinkedConnections")
    :param service: a Service instance representing a connection to a Splunk instance
    :param pbar_data: the encapsulated info needed for logging w/ pbar
    :param test_index: the index attack data is forwarded to for testing (optionally used in cleanup)
    """
    ## The following three fields are explicitly needed at instantiation                            # noqa: E266

    # the name of the search/detection (e.g. "Windows Modify Registry EnableLinkedConnections")
    detection_name: str

    # a Service instance representing a connection to a Splunk instance
    service: splunklib.Service

    # the encapsulated info needed for logging w/ pbar
    pbar_data: PbarData

    ## The following field is optional for instantiation                                            # noqa: E266

    # The index attack data is sent to; can be None if we are relying on the caller to do our
    # cleanup of this index
    test_index: Optional[str] = Field(default=None, min_length=1)

    ## All remaining fields can be derived from other fields or have intentional defaults that      # noqa: E266
    ## should not be changed (validators should prevent instantiating some of these fields directly # noqa: E266
    ## to prevent undefined behavior)                                                               # noqa: E266

    # The logger to use (logs all go to a null pipe unless ENABLE_LOGGING is set to True, so as not
    # to conflict w/ tqdm)
    logger: logging.Logger = Field(default_factory=get_logger)

    # The search name (e.g. "ESCU - Windows Modify Registry EnableLinkedConnections - Rule")
    name: Optional[str] = None

    # The path to the saved search on the Splunk instance
    splunk_path: Optional[str] = None

    # A model of the saved search as provided by splunklib
    saved_search: Optional[splunklib.SavedSearch] = None

    # The set of indexes to clear on cleanup
    indexes_to_purge: set[str] = set()

    # The risk analysis adaptive response action (if defined)
    risk_analysis_action: Union[RiskAnalysisAction, None] = None

    # The notable adaptive response action (if defined)
    notable_action: Union[NotableAction, None] = None

    class Config:
        # needed to allow fields w/ types like SavedSearch
        arbitrary_types_allowed = True

    @validator("name", always=True)
    @classmethod
    def _convert_detection_to_search_name(cls, v, values) -> str:
        """
        Validate detection name and derive if None
        """
        if "detection_name" not in values:
            raise ValueError("detection_name missing; name is dependent on detection_name")

        expected_name = f"ESCU - {values['detection_name']} - Rule"
        if v is not None and v != expected_name:
            raise ValueError(
                "name must be derived from detection_name; leave as None and it will be derived automatically"
            )
        return f"ESCU - {values['detection_name']} - Rule"

    @validator("splunk_path", always=True)
    @classmethod
    def _derive_splunk_path(cls, v, values) -> str:
        """
        Validate splunk_path and derive if None
        """
        if "name" not in values:
            raise ValueError("name missing; splunk_path is dependent on name")

        expected_path = f"saved/searches/{values['name']}"
        if v is not None and v != expected_path:
            raise ValueError(
                "splunk_path must be derived from name; leave as None and it will be derived automatically"
            )
        return f"saved/searches/{values['name']}"

    @validator("saved_search", always=True)
    @classmethod
    def _instantiate_saved_search(cls, v, values) -> str:
        """
        Ensure saved_search was initialized as None and derive
        """
        if "splunk_path" not in values or "service" not in values:
            raise ValueError("splunk_path or service missing; saved_search is dependent on both")

        if v is not None:
            raise ValueError(
                "saved_search must be derived from the service and splunk_path; leave as None and it will be derived "
                "automatically"
            )
        return splunklib.SavedSearch(
            values['service'],
            values['splunk_path'],
        )

    @validator("risk_analysis_action", always=True)
    @classmethod
    def _init_risk_analysis_action(cls, v, values) -> Optional[RiskAnalysisAction]:
        """
        Initialize risk_analysis_action
        """
        if "saved_search" not in values:
            raise ValueError("saved_search missing; risk_analysis_action is dependent on saved_search")

        if v is not None:
            raise ValueError(
                "risk_analysis_action must be derived from the saved_search; leave as None and it will be derived "
                "automatically"
            )
        return CorrelationSearch._get_risk_analysis_action(values['saved_search'].content)

    @validator("notable_action", always=True)
    @classmethod
    def _init_notable_action(cls, v, values) -> Optional[NotableAction]:
        """
        Initialize notable_action
        """
        if "saved_search" not in values:
            raise ValueError("saved_search missing; notable_action is dependent on saved_search")

        if v is not None:
            raise ValueError(
                "notable_action must be derived from the saved_search; leave as None and it will be derived "
                "automatically"
            )
        return CorrelationSearch._get_notable_action(values['saved_search'].content)

    @property
    def earliest_time(self) -> str:
        """
        The earliest time configured for the saved search
        """
        if self.saved_search is not None:
            return self.saved_search.content[SavedSearchKeys.EARLIEST_TIME_KEY.value]
        else:
            raise ClientError("Something unexpected went wrong in initialization; saved_search was not populated")

    @property
    def latest_time(self) -> str:
        """
        The latest time configured for the saved search
        """
        if self.saved_search is not None:
            return self.saved_search.content[SavedSearchKeys.LATEST_TIME_KEY.value]
        else:
            raise ClientError("Something unexpected went wrong in initialization; saved_search was not populated")

    @property
    def cron_schedule(self) -> str:
        """
        The cron schedule configured for the saved search
        """
        if self.saved_search is not None:
            return self.saved_search.content[SavedSearchKeys.CRON_SCHEDULE_KEY.value]
        else:
            raise ClientError("Something unexpected went wrong in initialization; saved_search was not populated")

    @property
    def enabled(self) -> bool:
        """
        Whether the saved search is enabled
        """
        if self.saved_search is not None:
            if int(self.saved_search.content[SavedSearchKeys.DISBALED_KEY.value]):
                return False
            else:
                return True
        else:
            raise ClientError("Something unexpected went wrong in initialization; saved_search was not populated")

    @ property
    def has_risk_analysis_action(self) -> bool:
        """Whether the correlation search has an associated risk analysis Adaptive Response Action
        :return: a boolean indicating whether it has a risk analysis Adaptive Response Action
        """
        return self.risk_analysis_action is not None

    @property
    def has_notable_action(self) -> bool:
        """Whether the correlation search has an associated notable Adaptive Response Action
        :return: a boolean indicating whether it has a notable Adaptive Response Action
        """
        return self.notable_action is not None

    @staticmethod
    def _get_risk_analysis_action(content: dict[str, Any]) -> Optional[RiskAnalysisAction]:
        """
        Given the saved search content, parse the risk analysis action
        :param content: a dict of strings to values
        :returns: a RiskAnalysisAction, or None if none exists
        """
        if int(content[SavedSearchKeys.RISK_ACTION_KEY.value]):
            try:
                return RiskAnalysisAction.parse_from_dict(content)
            except ValueError as e:
                raise ClientError(f"Error unpacking RiskAnalysisAction: {e}")
        return None

    @staticmethod
    def _get_notable_action(content: dict[str, Any]) -> Optional[NotableAction]:
        """
        Given the saved search content, parse the notable action
        :param content: a dict of strings to values
        :returns: a NotableAction, or None if none exists
        """
        # grab notable details if present
        if int(content[SavedSearchKeys.NOTABLE_ACTION_KEY.value]):
            return NotableAction.parse_from_dict(content)
        return None

    # TODO (cmcginley): ideally, we could handle this and the following init w/ a call to
    #   model_post_init, so that all the logic is encapsulated w/in _parse_risk_and_notable_actions
    #   but that is a pydantic v2 feature (see the init validators for risk/notable actions):
    #   https://docs.pydantic.dev/latest/api/base_model/#pydantic.main.BaseModel.model_post_init
    def _parse_risk_and_notable_actions(self) -> None:
        """Parses the risk/notable metadata we care about from self.saved_search.content

        :raises KeyError: if self.saved_search.content does not contain a required key
        :raises json.JSONDecodeError: if the value at self.saved_search.content['action.risk.param._risk'] can't be
            decoded from JSON into a dict
        :raises IntegrationTestingError: if the value at self.saved_search.content['action.risk.param._risk'] is
            unpacked to be anything other than a singleton
        """
        # grab risk details if present
        self.risk_analysis_action = CorrelationSearch._get_risk_analysis_action(
            self.saved_search.content                                                               # type: ignore
        )

        # grab notable details if present
        self.notable_action = CorrelationSearch._get_notable_action(self.saved_search.content)      # type: ignore

    def refresh(self) -> None:
        """Refreshes the metadata in the SavedSearch entity, and re-parses the fields we care about

        After operations we expect to alter the state of the SavedSearch, we call refresh so that we have a local
        representation of the new state; then we extrat what we care about into this instance
        """
        self.logger.debug(
            f"Refreshing SavedSearch metadata for {self.name}...")
        try:
            self.saved_search.refresh()                                                             # type: ignore
        except HTTPError as e:
            raise ServerError(f"HTTP error encountered during refresh: {e}")
        self._parse_risk_and_notable_actions()

    def enable(self, refresh: bool = True) -> None:
        """Enables the SavedSearch

        Enable the SavedSearch entity, optionally calling self.refresh() (optional, because in some situations the
        caller may want to handle calling refresh, to avoid repeated network operations).
        :param refresh: a bool indicating whether to run refresh after enabling
        """
        self.logger.debug(f"Enabling {self.name}...")
        try:
            self.saved_search.enable()                                                              # type: ignore
        except HTTPError as e:
            raise ServerError(f"HTTP error encountered while enabling detection: {e}")
        if refresh:
            self.refresh()

    def disable(self, refresh: bool = True) -> None:
        """Disables the SavedSearch

        Disable the SavedSearch entity, optionally calling self.refresh() (optional, because in some situations the
        caller may want to handle calling refresh, to avoid repeated network operations).
        :param refresh: a bool indicating whether to run refresh after disabling
        """
        self.logger.debug(f"Disabling {self.name}...")
        try:
            self.saved_search.disable()                                                             # type: ignore
        except HTTPError as e:
            raise ServerError(f"HTTP error encountered while disabling detection: {e}")
        if refresh:
            self.refresh()

    def update_timeframe(
        self,
        earliest_time: str = ScheduleConfig.EARLIEST_TIME.value,
        latest_time: str = ScheduleConfig.LATEST_TIME.value,
        cron_schedule: str = ScheduleConfig.CRON_SCHEDULE.value,
        refresh: bool = True
    ) -> None:
        """Updates the correlation search timeframe to work with test data

        Updates the correlation search timeframe such that it runs according to the given cron schedule, and that the
        data it runs on is no older than the given earliest time and no newer than the given latest time; optionally
        calls self.refresh() (optional, because in some situations the caller may want to handle calling refresh, to
        avoid repeated network operations).
        :param earliest_time: the max age of data for the search to run on (default: see ScheduleConfig)
        :param earliest_time: the max age of data for the search to run on (default: see ScheduleConfig)
        :param cron_schedule: the cron schedule for the search to run on (default: see ScheduleConfig)
        :param refresh: a bool indicating whether to run refresh after enabling
        """
        # update the SavedSearch accordingly
        data = {
            SavedSearchKeys.EARLIEST_TIME_KEY.value: earliest_time,
            SavedSearchKeys.LATEST_TIME_KEY.value: latest_time,
            SavedSearchKeys.CRON_SCHEDULE_KEY.value: cron_schedule
        }
        self.logger.info(data)
        self.logger.info(f"Updating timeframe for '{self.name}': {data}")
        try:
            self.saved_search.update(**data)                                                        # type: ignore
        except HTTPError as e:
            raise ServerError(f"HTTP error encountered while updating timeframe: {e}")

        if refresh:
            self.refresh()

    def force_run(self, refresh=True) -> None:
        """Forces a detection run

        Enables the detection, adjusts the cron schedule to run every 1 minute, and widens the earliest/latest window
        to run on test data.
        :param refresh: a bool indicating whether to refresh the metadata for the detection (default True)
        """
        self.update_timeframe(refresh=False)
        if not self.enabled:
            self.enable(refresh=False)
        else:
            self.logger.warn(f"Detection '{self.name}' was already enabled")

        if refresh:
            self.refresh()

    # TODO (cmcginley): make the search for risk/notable events a more specific query based on the
    #   search in question (and update the docstring to relfect when you do)
    def risk_event_exists(self) -> bool:
        """Whether a risk event exists

        Queries the `risk` index and returns True if a risk event exists
        :return: a bool indicating whether a risk event exists in the risk index
        """
        # construct our query and issue our search job on the risk index
        query = "search index=risk | head 1"
        result_iterator = self._search(query)
        try:
            for result in result_iterator:
                # we return True if we find at least one risk object
                # (e.g. users vs systems) and we may want to do more confirmational testing
                if result["index"] == Indexes.RISK_INDEX.value:
                    self.logger.debug(
                        f"Found risk event for '{self.name}': {result}")
                    return True
        except ServerError as e:
            self.logger.error(f"Error returned from Splunk instance: {e}")
            raise e
        self.logger.debug(f"No risk event found for '{self.name}'")
        return False

    def notable_event_exists(self) -> bool:
        """Whether a notable event exists

        Queries the `notable` index and returns True if a risk event exists
        :return: a bool indicating whether a risk event exists in the risk index
        """
        # construct our query and issue our search job on the risk index
        query = "search index=notable | head 1"
        result_iterator = self._search(query)
        try:
            for result in result_iterator:
                # we return True if we find at least one notable object
                if result["index"] == Indexes.NOTABLE_INDEX.value:
                    self.logger.debug(
                        f"Found notable event for '{self.name}': {result}")
                    return True
        except ServerError as e:
            self.logger.error(f"Error returned from Splunk instance: {e}")
            raise e
        self.logger.debug(f"No notable event found for '{self.name}'")
        return False

    def risk_message_is_valid(self) -> bool:
        """Validates the observed risk message against the expected risk message"""
        # TODO
        raise NotImplementedError

    # NOTE: it would be more ideal to switch this to a system which gets the handle of the saved search job and polls
    #   it for completion, but that seems more tricky
    def test(self, max_sleep: int = TimeoutConfig.MAX_SLEEP.value, raise_on_exc: bool = False) -> IntegrationTestResult:
        """Execute the integration test

        Executes an integration test for this CorrelationSearch. First, ensures no matching risk/notables already exist
        and clear the indexes if so. Then, we force a run of the detection, wait for `sleep` seconds, and finally we
        validate that the appropriate risk/notable events seem to have been created. NOTE: assumes the data already
        exists in the instance
        :param max_sleep: max number of seconds to sleep for after enabling the detection before we check for created
            events; re-checks are made upon failures using an exponential backoff until the max is reached
        :param raise_on_exc: bool flag indicating if an exception should be raised when caught by the test routine, or
            if the error state should just be recorded for the test
        """
        # max_sleep must be greater than the base value we must wait for the scheduled searchjob to run (jobs run every
        # 60s)
        if max_sleep < TimeoutConfig.BASE_SLEEP.value:
            raise ClientError(
                f"max_sleep value of {max_sleep} is less than the base sleep required "
                f"({TimeoutConfig.BASE_SLEEP.value})"
            )

        # initialize result as None
        result: Optional[IntegrationTestResult] = None

        # keep track of time slept and number of attempts for exponential backoff (base 2)
        elapsed_sleep_time = 0
        num_tries = 0

        # set the initial base sleep time
        time_to_sleep = TimeoutConfig.BASE_SLEEP.value

        try:
            # first make sure the indexes are currently empty and the detection is starting from a disabled state
            self.logger.debug(
                "Cleaning up any pre-existing risk/notable events..."
            )
            self.update_pbar(TestingStates.PRE_CLEANUP)
            if self.risk_event_exists():
                self.logger.warn(
                    f"Risk events matching '{self.name}' already exist; marking for deletion")
                self.indexes_to_purge.add(Indexes.RISK_INDEX.value)
            if self.notable_event_exists():
                self.logger.warn(
                    f"Notable events matching '{self.name}' already exist; marking for deletion")
                self.indexes_to_purge.add(Indexes.NOTABLE_INDEX.value)
            self.cleanup()

            # skip test if no risk or notable action defined
            if not self.has_risk_analysis_action and not self.has_notable_action:
                message = (
                    f"TEST SKIPPED: No risk analysis or notable Adaptive Response actions defined; "
                    f"skipping integration test: {self.name}"
                )
                result = IntegrationTestResult(
                    message=message,
                    status=TestResultStatus.SKIP,
                    wait_duration=0,
                )
            else:
                # force the detection to run
                self.logger.info(f"Forcing a run on {self.name}")
                self.update_pbar(TestingStates.FORCE_RUN)
                self.force_run()
                time.sleep(TimeoutConfig.BASE_SLEEP.value)

                # loop so long as the elapsed time is less than max_sleep
                while elapsed_sleep_time < max_sleep:
                    # sleep so the detection job can finish
                    self.logger.info(f"Waiting {time_to_sleep} for {self.name} so it can finish")
                    self.update_pbar(TestingStates.VALIDATING)
                    time.sleep(time_to_sleep)
                    elapsed_sleep_time += time_to_sleep

                    self.logger.info(
                        f"Validating detection (attempt #{num_tries + 1} - {elapsed_sleep_time} seconds elapsed of "
                        f"{max_sleep} max)"
                    )

                    # reset the result to None on each loop iteration
                    result = None

                    # TODO (cmcginley): add more granular error messaging that can show success in
                    #   finding a notable, but failure in finding a risk and vice-versa
                    # check for risk events
                    self.logger.debug("Checking for matching risk events")
                    if self.has_risk_analysis_action:
                        if not self.risk_event_exists():
                            result = IntegrationTestResult(
                                status=TestResultStatus.FAIL,
                                message=f"TEST FAILED: No matching risk event created for: {self.name}",
                                wait_duration=elapsed_sleep_time,
                            )
                        else:
                            self.indexes_to_purge.add(Indexes.RISK_INDEX.value)

                    # check for notable events
                    self.logger.debug("Checking for matching notable events")
                    if self.has_notable_action:
                        if not self.notable_event_exists():
                            # NOTE: because we check this last, if both fail, the error message about notables will
                            # always be the last to be added and thus the one surfaced to the user; good case for
                            # adding more descriptive test results
                            result = IntegrationTestResult(
                                status=TestResultStatus.FAIL,
                                message=f"TEST FAILED: No matching notable event created for: {self.name}",
                                wait_duration=elapsed_sleep_time,
                            )
                        else:
                            self.indexes_to_purge.add(Indexes.NOTABLE_INDEX.value)

                    # if result is still None, then all checks passed and we can break the loop
                    if result is None:
                        result = IntegrationTestResult(
                            status=TestResultStatus.PASS,
                            message=f"TEST PASSED: Expected risk and/or notable events were created for: {self.name}",
                            wait_duration=elapsed_sleep_time,
                        )
                        break

                    # increment number of attempts to validate detection
                    num_tries += 1

                    # compute the next time to sleep for
                    time_to_sleep = 2**num_tries

                    # if the computed time to sleep will exceed max_sleep, adjust appropriately
                    if (elapsed_sleep_time + time_to_sleep) > max_sleep:
                        time_to_sleep = max_sleep - elapsed_sleep_time

            # cleanup the created events, disable the detection and return the result
            self.logger.debug("Cleaning up any created risk/notable events...")
            self.update_pbar(TestingStates.POST_CLEANUP)
            self.cleanup()
        except IntegrationTestingError as e:
            if not raise_on_exc:
                result = IntegrationTestResult(
                    status=TestResultStatus.ERROR,
                    message=f"TEST FAILED (ERROR): Exception raised during integration test: {e}",
                    wait_duration=elapsed_sleep_time,
                    exception=e,
                )
                self.logger.exception(f"{result.status.name}: {result.message}")                    # type: ignore
            else:
                raise e

        # log based on result status
        if result is not None:
            if result.status == TestResultStatus.PASS or result.status == TestResultStatus.SKIP:
                self.logger.info(f"{result.status.name}: {result.message}")
            elif result.status == TestResultStatus.FAIL:
                self.logger.error(f"{result.status.name}: {result.message}")
            elif result.status != TestResultStatus.ERROR:
                message = f"Unexpected result status code: {result.status}"
                self.logger.error(message)
                raise ClientError(message)
        else:
            message = "Result was not generated; something went wrong..."
            self.logger.error(message)
            raise ClientError(message)

        return result

    def _search(self, query: str) -> ResultIterator:
        """Execute a search job against the Splunk instance

        Given a query, creates a search job on the Splunk instance. Jobs are created in blocking mode and won't return
        until results ready.
        :param query: the SPL string to run
        """
        self.logger.debug(f"Executing query: `{query}`")
        job = self.service.search(query, exec_mode="blocking")

        # query the results, catching any HTTP status code errors
        try:
            response_reader: ResponseReader = job.results(output_mode="json")
        except HTTPError as e:
            # e.g. ->  HTTP 400 Bad Request -- b'{"messages":[{"type":"FATAL","text":"Error in \'delete\' command: You
            #   have insufficient privileges to delete events."}]}'
            message = f"Error querying Splunk instance: {e}"
            self.logger.error(message)
            raise ServerError(message)

        return ResultIterator(response_reader)

    def _delete_index(self, index: str) -> None:
        """Deletes events in a given index

        Given an index, purge all events from it
        :param index: index to delete all events from (e.g. 'risk')
        """
        # construct our query and issue our delete job on the index
        self.logger.debug(f"Deleting index '{index}")
        query = f"search index={index} | delete"
        result_iterator = self._search(query)

        # we should get two results, one for "__ALL__" and one for the index; iterate until we find the one for the
        # given index
        found_index = False
        for result in result_iterator:
            if result["index"] == index:
                found_index = True
                self.logger.info(
                    f"Deleted {result['deleted']} from index {result['index']} with {result['errors']} errors"
                )

                # check for errors
                if result["errors"] != "0":
                    message = f"Errors encountered during delete operation on index {self.name}"
                    raise ServerError(message)

        # raise an error if we never encountered a result showing a delete operation in the given index
        if not found_index:
            message = f"No result returned showing deletion in index {index}"
            raise ServerError(message)

    def cleanup(self, delete_test_index=False) -> None:
        """Cleans up after an integration test

        First, disable the detection; then dump the risk, notable, and (optionally) test indexes. The test index is
        optional because the contentctl capability we will be piggybacking on has it's own cleanup routine.
        NOTE: This does not restore the detection/search to it's original state; changes made to earliest/latest time
        and the cron schedule persist after cleanup
        :param delete_test_index: flag indicating whether the test index should be cleared or not (defaults to False)
        """
        # delete_test_index can't be true when test_index is None
        if delete_test_index and (self.test_index is None):
            raise ClientError("test_index is None, cannot delete it")

        # disable the detection
        self.disable()

        # delete the indexes
        if delete_test_index:
            self.indexes_to_purge.add(self.test_index)                                              # type: ignore
        for index in self.indexes_to_purge:
            self._delete_index(index)
        self.indexes_to_purge.clear()

    def update_pbar(self, state: str) -> str:
        """
        Instance specific function to log integrtation testing information via pbar
        :param state: the state/message of the test to be logged
        :returns: a formatted string for use w/ pbar
        """
        # invoke the helper method on our instance attrs and return
        return format_pbar_string(
            self.pbar_data.pbar,
            TestReportingType.INTEGRATION,
            self.pbar_data.fq_test_name,
            state,
            self.pbar_data.start_time,
            True
        )
