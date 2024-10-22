import logging
import time
import json
from typing import Any
from enum import Enum
from functools import cached_property

from pydantic import ConfigDict, BaseModel, computed_field, Field, PrivateAttr
from splunklib.results import JSONResultsReader, Message                                            # type: ignore
from splunklib.binding import HTTPError, ResponseReader                                             # type: ignore
import splunklib.client as splunklib                                                                # type: ignore
from tqdm import tqdm                                                                               # type: ignore

from contentctl.objects.risk_analysis_action import RiskAnalysisAction
from contentctl.objects.notable_action import NotableAction
from contentctl.objects.base_test_result import TestResultStatus
from contentctl.objects.integration_test_result import IntegrationTestResult
from contentctl.actions.detection_testing.progress_bar import (
    format_pbar_string,                                                                             # type: ignore
    TestReportingType,
    TestingStates
)
from contentctl.objects.errors import (
    IntegrationTestingError,
    ServerError,
    ClientError,
    ValidationFailed
)
from contentctl.objects.detection import Detection
from contentctl.objects.risk_event import RiskEvent
from contentctl.objects.notable_event import NotableEvent
from contentctl.objects.observable import Observable


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

    # NOTE: Some detections take longer to generate their risk/notables than other; testing has
    #   shown 270s to likely be sufficient for all detections in 99% of runs; however we have
    #   encountered a handful of transient failures in the last few months. Since our success rate
    #   is at 100% now, we will round this to a flat 300s to accomodate these outliers.
    # Max amount to wait before timing out during exponential backoff
    MAX_SLEEP = 300


# TODO (#226): evaluate sane defaults for timeframe for integration testing (e.g. 5y is good
#   now, but maybe not always...); maybe set latest/earliest to None?
class ScheduleConfig(str, Enum):
    """
    Configuraton values for the saved search schedule
    """
    EARLIEST_TIME = "-5y@y"
    LATEST_TIME = "-1m@m"
    CRON_SCHEDULE = "*/1 * * * *"


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
                message = f"SPLUNK: {result.message}"
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
    pbar: tqdm                                                                                      # type: ignore
    fq_test_name: str
    start_time: float

    # needed to support the tqdm type
    model_config = ConfigDict(
        arbitrary_types_allowed=True
    )


class CorrelationSearch(BaseModel):
    """Representation of a correlation search in Splunk

    In Enterprise Security, a correlation search is wrapper around the saved search entity. This search represents a
    detection rule for our purposes.
    :param detection: a Detection model
    :param service: a Service instance representing a connection to a Splunk instance
    :param pbar_data: the encapsulated info needed for logging w/ pbar
    :param test_index: the index attack data is forwarded to for testing (optionally used in cleanup)
    """
    # the detection associated with the correlation search (e.g. "Windows Modify Registry EnableLinkedConnections")
    detection: Detection = Field(...)

    # a Service instance representing a connection to a Splunk instance
    service: splunklib.Service = Field(...)

    # the encapsulated info needed for logging w/ pbar
    pbar_data: PbarData = Field(...)

    # The index attack data is sent to; can be None if we are relying on the caller to do our
    # cleanup of this index
    test_index: str | None = Field(default=None, min_length=1)

    # The logger to use (logs all go to a null pipe unless ENABLE_LOGGING is set to True, so as not
    # to conflict w/ tqdm)
    logger: logging.Logger = Field(default_factory=get_logger, init=False)

    # The set of indexes to clear on cleanup
    indexes_to_purge: set[str] = Field(default=set(), init=False)

    # The risk analysis adaptive response action (if defined)
    _risk_analysis_action: RiskAnalysisAction | None = PrivateAttr(default=None)

    # The notable adaptive response action (if defined)
    _notable_action: NotableAction | None = PrivateAttr(default=None)

    # The list of risk events found
    _risk_events: list[RiskEvent] | None = PrivateAttr(default=None)

    # The list of notable events found
    _notable_events: list[NotableEvent] | None = PrivateAttr(default=None)

    # Need arbitrary types to allow fields w/ types like SavedSearch; we also want to forbid
    # unexpected fields
    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        extra='forbid'
    )

    def model_post_init(self, __context: Any) -> None:
        super().model_post_init(__context)

        # Parse the initial values for the risk/notable actions
        self._parse_risk_and_notable_actions()

    @computed_field
    @cached_property
    def name(self) -> str:
        """
        The search name (e.g. "ESCU - Windows Modify Registry EnableLinkedConnections - Rule")

        :returns: the search name
        :rtype: str
        """
        return f"ESCU - {self.detection.name} - Rule"

    @computed_field
    @cached_property
    def splunk_path(self) -> str:
        """
        The path to the saved search on the Splunk instance

        :returns: the search path
        :rtype: str
        """
        return f"saved/searches/{self.name}"

    @computed_field
    @cached_property
    def saved_search(self) -> splunklib.SavedSearch:
        """
        A model of the saved search as provided by splunklib

        :returns: the SavedSearch object
        :rtype: :class:`splunklib.client.SavedSearch`
        """
        return splunklib.SavedSearch(
            self.service,
            self.splunk_path,
        )

    # TODO (cmcginley): need to make this refreshable
    @computed_field
    @property
    def risk_analysis_action(self) -> RiskAnalysisAction | None:
        """
        The risk analysis adaptive response action (if defined)

        :returns: the RiskAnalysisAction object, if it exists
        :rtype: :class:`contentctl.objects.risk_analysis_action.RiskAnalysisAction` | None
        """
        return self._risk_analysis_action

    # TODO (cmcginley): need to make this refreshable
    @computed_field
    @property
    def notable_action(self) -> NotableAction | None:
        """
        The notable adaptive response action (if defined)

        :returns: the NotableAction object, if it exists
        :rtype: :class:`contentctl.objects.notable_action.NotableAction` | None
        """
        return self._notable_action

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
    def _get_risk_analysis_action(content: dict[str, Any]) -> RiskAnalysisAction | None:
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
    def _get_notable_action(content: dict[str, Any]) -> NotableAction | None:
        """
        Given the saved search content, parse the notable action
        :param content: a dict of strings to values
        :returns: a NotableAction, or None if none exists
        """
        # grab notable details if present
        if int(content[SavedSearchKeys.NOTABLE_ACTION_KEY.value]):
            return NotableAction.parse_from_dict(content)
        return None

    @staticmethod
    def _get_relevant_observables(observables: list[Observable]) -> list[Observable]:
        """
        Given a list of observables, identify the subset of those relevant for risk matching
        :param observables: the Observable objects to filter
        :returns: the filtered list of relevant observables
        """
        relevant = []
        for observable in observables:
            if not RiskEvent.ignore_observable(observable):
                relevant.append(observable)
        return relevant

    def _parse_risk_and_notable_actions(self) -> None:
        """Parses the risk/notable metadata we care about from self.saved_search.content

        :raises KeyError: if self.saved_search.content does not contain a required key
        :raises json.JSONDecodeError: if the value at self.saved_search.content['action3.risk.param._risk'] can't be
            decoded from JSON into a dict
        :raises IntegrationTestingError: if the value at self.saved_search.content['action.risk.param._risk'] is
            unpacked to be anything other than a singleton
        """
        # grab risk details if present
        self._risk_analysis_action = CorrelationSearch._get_risk_analysis_action(
            self.saved_search.content                                                               # type: ignore
        )

        # grab notable details if present
        self._notable_action = CorrelationSearch._get_notable_action(self.saved_search.content)     # type: ignore

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

    def risk_event_exists(self) -> bool:
        """Whether at least one matching risk event exists

        Queries the `risk` index and returns True if at least one matching risk event exists for
        this search
        :return: a bool indicating whether a risk event for this search exists in the risk index
        """
        # We always force an update on the cache when checking if events exist
        events = self.get_risk_events(force_update=True)
        return len(events) > 0

    def get_risk_events(self, force_update: bool = False) -> list[RiskEvent]:
        """Get risk events from the Splunk instance

        Queries the `risk` index and returns any matching risk events
        :param force_update: whether the cached _risk_events should be forcibly updated if already
            set
        :return: a list of risk events
        """
        # Reset the list of risk events if we're forcing an update
        if force_update:
            self.logger.debug("Resetting risk event cache.")
            self._risk_events = None

        # Use the cached risk_events unless we're forcing an update
        if self._risk_events is not None:
            self.logger.debug(f"Using cached risk events ({len(self._risk_events)} total).")
            return self._risk_events

        # TODO (#248): Refactor risk/notable querying to pin to a single savedsearch ID
        # Search for all risk events from a single scheduled search (indicated by orig_sid)
        query = (
            f'search index=risk search_name="{self.name}" [search index=risk search '
            f'search_name="{self.name}" | tail 1 | fields orig_sid] | tojson'
        )
        result_iterator = self._search(query)

        # Iterate over the events, storing them in a list and checking for any errors
        events: list[RiskEvent] = []
        try:
            for result in result_iterator:
                # sanity check that this result from the iterator is a risk event and not some
                # other metadata
                if result["index"] == Indexes.RISK_INDEX.value:
                    try:
                        parsed_raw = json.loads(result["_raw"])
                        event = RiskEvent.parse_obj(parsed_raw)
                    except Exception:
                        self.logger.error(f"Failed to parse RiskEvent from search result: {result}")
                        raise
                    events.append(event)
                    self.logger.debug(f"Found risk event for '{self.name}': {event}")
        except ServerError as e:
            self.logger.error(f"Error returned from Splunk instance: {e}")
            raise e

        # Log if no events were found
        if len(events) < 1:
            self.logger.debug(f"No risk events found for '{self.name}'")
        else:
            # Set the cache if we found events
            self._risk_events = events
            self.logger.debug(f"Caching {len(self._risk_events)} risk events.")

        return events

    def notable_event_exists(self) -> bool:
        """Whether a notable event exists

        Queries the `notable` index and returns True if a notble event exists
        :return: a bool indicating whether a notable event exists in the notable index
        """
        # construct our query and issue our search job on the notsble index
        # We always force an update on the cache when checking if events exist
        events = self.get_notable_events(force_update=True)
        return len(events) > 0

    def get_notable_events(self, force_update: bool = False) -> list[NotableEvent]:
        """Get notable events from the Splunk instance

        Queries the `notable` index and returns any matching notable events
        :param force_update: whether the cached _notable_events should be forcibly updated if
            already set
        :return: a list of notable events
        """
        # Reset the list of notable events if we're forcing an update
        if force_update:
            self.logger.debug("Resetting notable event cache.")
            self._notable_events = None

        # Use the cached notable_events unless we're forcing an update
        if self._notable_events is not None:
            self.logger.debug(f"Using cached notable events ({len(self._notable_events)} total).")
            return self._notable_events

        # Search for all notable events from a single scheduled search (indicated by orig_sid)
        query = (
            f'search index=notable search_name="{self.name}" [search index=notable search '
            f'search_name="{self.name}" | tail 1 | fields orig_sid] | tojson'
        )
        result_iterator = self._search(query)

        # Iterate over the events, storing them in a list and checking for any errors
        events: list[NotableEvent] = []
        try:
            for result in result_iterator:
                # sanity check that this result from the iterator is a notable event and not some
                # other metadata
                if result["index"] == Indexes.NOTABLE_INDEX.value:
                    try:
                        parsed_raw = json.loads(result["_raw"])
                        event = NotableEvent.parse_obj(parsed_raw)
                    except Exception:
                        self.logger.error(f"Failed to parse NotableEvent from search result: {result}")
                        raise
                    events.append(event)
                    self.logger.debug(f"Found notable event for '{self.name}': {event}")
        except ServerError as e:
            self.logger.error(f"Error returned from Splunk instance: {e}")
            raise e

        # Log if no events were found
        if len(events) < 1:
            self.logger.debug(f"No notable events found for '{self.name}'")
        else:
            # Set the cache if we found events
            self._notable_events = events
            self.logger.debug(f"Caching {len(self._notable_events)} notable events.")

        return events

    def validate_risk_events(self) -> None:
        """Validates the existence of any expected risk events

        First ensure the risk event exists, and if it does validate its risk message and make sure
        any events align with the specified observables. Also adds the risk index to the purge list
        if risk events existed
        :param elapsed_sleep_time: an int representing the amount of time slept thus far waiting to
            check the risks/notables
        :returns: an IntegrationTestResult on failure; None on success
        """
        # Create a mapping of the relevant observables to counters
        observables = CorrelationSearch._get_relevant_observables(self.detection.tags.observable)
        observable_counts: dict[str, int] = {str(x): 0 for x in observables}

        # NOTE: we intentionally want this to be an error state and not a failure state, as
        #   ultimately this validation should be handled during the build process
        if len(observables) != len(observable_counts):
            raise ClientError(
                f"At least two observables in '{self.detection.name}' have the same name; "
                "each observable for a detection should be unique."
            )

        # Get the risk events; note that we use the cached risk events, expecting they were
        # saved by a prior call to risk_event_exists
        events = self.get_risk_events()

        # Validate each risk event individually and record some aggregate counts
        c = 0
        for event in events:
            c += 1
            self.logger.debug(
                f"Validating risk event ({event.risk_object}, {event.risk_object_type}): "
                f"{c}/{len(events)}"
            )
            event.validate_against_detection(self.detection)

            # Update observable count based on match
            matched_observable = event.get_matched_observable(self.detection.tags.observable)
            self.logger.debug(
                f"Matched risk event (object={event.risk_object}, type={event.risk_object_type}) "
                f"to observable (name={matched_observable.name}, type={matched_observable.type}, "
                f"role={matched_observable.role}) using the source field "
                f"'{event.source_field_name}'"
            )
            observable_counts[str(matched_observable)] += 1

        # Report any observables which did not have at least one match to a risk event
        for observable in observables:
            self.logger.debug(
                f"Matched observable (name={observable.name}, type={observable.type}, "
                f"role={observable.role}) to {observable_counts[str(observable)]} risk events."
            )
            if observable_counts[str(observable)] == 0:
                raise ValidationFailed(
                    f"Observable (name={observable.name}, type={observable.type}, "
                    f"role={observable.role}) was not matched to any risk events."
                )

        # TODO (#250): Re-enable and refactor code that validates the specific risk counts
        # Validate risk events in aggregate; we should have an equal amount of risk events for each
        # relevant observable, and the total count should match the total number of events
        # individual_count: int | None = None
        # total_count = 0
        # for observable_str in observable_counts:
        #     self.logger.debug(
        #         f"Observable <{observable_str}> match count: {observable_counts[observable_str]}"
        #     )

        #     # Grab the first value encountered if not set yet
        #     if individual_count is None:
        #         individual_count = observable_counts[observable_str]
        #     else:
        #         # Confirm that the count for the current observable matches the count of the others
        #         if observable_counts[observable_str] != individual_count:
        #             raise ValidationFailed(
        #                 f"Count of risk events matching observable <\"{observable_str}\"> "
        #                 f"({observable_counts[observable_str]}) does not match the count of those "
        #                 f"matching other observables ({individual_count})."
        #             )

        #     # Aggregate total count of events matched to observables
        #     total_count += observable_counts[observable_str]

        # # Raise if the the number of events doesn't match the number of those matched to observables
        # if len(events) != total_count:
        #     raise ValidationFailed(
        #         f"The total number of risk events {len(events)} does not match the number of "
        #         f"risk events we were able to match against observables ({total_count})."
        #     )

    # TODO (PEX-434): implement deeper notable validation
    def validate_notable_events(self) -> None:
        """Validates the existence of any expected notables

        Ensures the notable exists. Also adds the notable index to the purge list if notables
        existed
        :param elapsed_sleep_time: an int representing the amount of time slept thus far waiting to
            check the risks/notables
        :returns: an IntegrationTestResult on failure; None on success
        """
        raise NotImplementedError()

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
        result: IntegrationTestResult | None = None

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
                    f"Risk events matching '{self.name}' already exist; marking for deletion"
                )
            if self.notable_event_exists():
                self.logger.warn(
                    f"Notable events matching '{self.name}' already exist; marking for deletion"
                )
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

                    try:
                        # Validate risk events
                        self.logger.debug("Checking for matching risk events")
                        if self.has_risk_analysis_action:
                            if self.risk_event_exists():
                                # TODO (PEX-435): should this in the retry loop? or outside it?
                                #   -> I've observed there being a missing risk event (15/16) on
                                #   the first few tries, so this does help us check for true
                                #   positives; BUT, if we have lots of failing detections, this
                                #   will definitely add to the total wait time
                                #   -> certain types of failures (e.g. risk message, or any value
                                #       checking) should fail testing automatically
                                #   -> other types, like those based on counts of risk events,
                                #       should happen should fail more slowly as more events may be
                                #       produced
                                self.validate_risk_events()
                            else:
                                raise ValidationFailed(
                                    f"TEST FAILED: No matching risk event created for: {self.name}"
                                )

                        # Validate notable events
                        self.logger.debug("Checking for matching notable events")
                        if self.has_notable_action:
                            # NOTE: because we check this last, if both fail, the error message about notables will
                            # always be the last to be added and thus the one surfaced to the user
                            if self.notable_event_exists():
                                # TODO (PEX-435): should this in the retry loop? or outside it?
                                # TODO (PEX-434): implement deeper notable validation (the method
                                #   commented out below is unimplemented)
                                # self.validate_notable_events(elapsed_sleep_time)
                                pass
                            else:
                                raise ValidationFailed(
                                    f"TEST FAILED: No matching notable event created for: {self.name}"
                                )
                    except ValidationFailed as e:
                        self.logger.error(f"Risk/notable validation failed: {e}")
                        result = IntegrationTestResult(
                            status=TestResultStatus.FAIL,
                            message=f"TEST FAILED: {e}",
                            wait_duration=elapsed_sleep_time,
                        )

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

            # TODO (PEX-436): should cleanup be in a finally block so it runs even on exception?
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
                self.logger.exception(result.message)                    # type: ignore
            else:
                raise e
        except Exception as e:
            # Log any exceptions locally and raise to the caller
            self.logger.exception(f"Unhandled exception during testing: {e}")
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
        self.logger.debug(f"Deleting index '{index}'")
        query = f'search index={index} search_name="{self.name}" | delete'
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

        # Add indexes to purge
        if delete_test_index:
            self.indexes_to_purge.add(self.test_index)                                              # type: ignore
        if self._risk_events is not None:
            self.indexes_to_purge.add(Indexes.RISK_INDEX.value)
        if self._notable_events is not None:
            self.indexes_to_purge.add(Indexes.NOTABLE_INDEX.value)

        # delete the indexes
        for index in self.indexes_to_purge:
            self._delete_index(index)
        self.indexes_to_purge.clear()

        # reset caches
        self._risk_events = None
        self._notable_events = None

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
