import json
import logging
import re
import time
import uuid
from functools import cached_property
from typing import Any, Callable

import splunklib.client as splunklib  # type: ignore
from pydantic import (
    BaseModel,
    Field,
    PrivateAttr,
    computed_field,
    model_validator,
)
from semantic_version import Version
from splunklib.binding import HTTPError, ResponseReader  # type: ignore
from splunklib.data import Record  # type: ignore

from contentctl.helper.utils import Utils
from contentctl.objects.config import Infrastructure, test_common
from contentctl.objects.correlation_search import ResultIterator
from contentctl.objects.detection import Detection

# Suppress logging by default; enable for local testing
ENABLE_LOGGING = False
LOG_LEVEL = logging.DEBUG
LOG_PATH = "content_versioning_service.log"

# The app name of ES; needed to check ES version
ES_APP_NAME = "SplunkEnterpriseSecuritySuite"


class CMSEvent(BaseModel):
    """
    A model representing a CMS event. This is used to validate that detections have been installed
    in a way that is compatible with content versioning.
    """

    content: str  # JSON string

    # The app name of the detection
    app_name: str

    # The detection id of the detection
    detection_id: str

    # The version of the detection
    version: str

    # The saved search name of the detection
    action_correlationsearch_label: str

    @model_validator(mode="before")
    @classmethod
    def extract_from_content(cls, data):
        """Extract fields from content JSON if not already provided"""
        if isinstance(data, dict) and "content" in data:
            try:
                content_str = data.get("content")
                parsed = json.loads(content_str)

                # Extract metadata fields - note the key has dots in it
                metadata_str = parsed.get("action.correlationsearch.metadata", {})
                metadata = (
                    json.loads(metadata_str)
                    if isinstance(metadata_str, str)
                    else metadata_str
                )
                data.setdefault("app_name", metadata.get("app_name"))
                data.setdefault("detection_id", metadata.get("detection_id"))
                data.setdefault("version", metadata.get("version"))
                data.setdefault(
                    "action_correlationsearch_label",
                    parsed.get("action.correlationsearch.label"),
                )
            except (json.JSONDecodeError, AttributeError, KeyError, TypeError):
                # If parsing fails, let Pydantic handle validation errors
                raise ValueError("Failed to parse content JSON {}".format(data))
        return data


class ContentVersioningService(BaseModel):
    """
    A model representing the content versioning service used in ES 8.0.0+. This model can be used
    to validate that detections have been installed in a way that is compatible with content
    versioning.
    """

    # The global contentctl config
    global_config: test_common

    # The instance specific infra config
    infrastructure: Infrastructure

    # The splunklib service
    service: splunklib.Service

    # The list of detections
    detections: list[Detection]

    # The logger to use (logs all go to a null pipe unless ENABLE_LOGGING is set to True, so as not
    # to conflict w/ tqdm)
    logger: logging.Logger = Field(
        default_factory=lambda: Utils.get_logger(
            __name__, LOG_LEVEL, LOG_PATH, ENABLE_LOGGING
        )
    )

    def model_post_init(self, __context: Any) -> None:
        super().model_post_init(__context)

        # Log instance details
        self.logger.info(
            f"[{self.infrastructure.instance_name} ({self.infrastructure.instance_address})] "
            "Initing ContentVersioningService"
        )

    # The cached job on the splunk instance of the cms events
    _cms_main_job: splunklib.Job | None = PrivateAttr(default=None)

    class Config:
        # We need to allow arbitrary type for the splunklib service
        arbitrary_types_allowed = True

    @computed_field
    @property
    def setup_functions(self) -> list[tuple[Callable[[], None], str]]:
        """
        Returns the list of setup functions needed for content versioning testing
        """
        return [
            (self.activate_versioning, "Activating Content Versioning"),
            (self.wait_for_cms_main, "Waiting for CMS Parser"),
            (self.validate_content_against_cms, "Validating Against CMS"),
        ]

    @cached_property
    def es_version(self) -> Version | None:
        """
        Returns the version of Enterprise Security installed on the instance; None if not installed.

        :return: the version of ES, as a semver aware object
        :rtype: :class:`semantic_version.Version`
        """
        if ES_APP_NAME not in self.service.apps:
            return None
        return Version(self.service.apps[ES_APP_NAME]["version"])  # type: ignore

    @cached_property
    def kvstore_content_versioning(self) -> bool:
        """
        Indicates whether we should test content versioning based on kvstore logic. Content versioning
        should be tested with kvstore logic when ES is at least version 8.3.0.

        :return: a bool indicating whether we should test content versioning with kvstore logic
        :rtype: bool
        """
        es_version = self.es_version
        return es_version is not None and es_version >= Version("8.3.0")

    @cached_property
    def indexbased_content_versioning(self) -> bool:
        """
        Indicates whether we should test content versioning based on indexbased logic. Content versioning
        should be tested with indexbased logic when ES is less than version 8.3.0 but greater than or equal
        to version 8.0.0.

        :return: a bool indicating whether we should test content versioning with indexbased logic
        :rtype: bool
        """
        es_version = self.es_version
        return (
            es_version is not None
            and es_version >= Version("8.0.0")
            and es_version < Version("8.3.0")
        )

    def _query_content_versioning_service(
        self, method: str, body: dict[str, Any] = {}
    ) -> Record:
        """
        Queries the SA-ContentVersioning service. Output mode defaults to JSON.

        :param method: HTTP request method (e.g. GET)
        :type method: str
        :param body: the payload/data/body of the request
        :type body: dict[str, Any]

        :returns: a splunklib Record object (wrapper around dict) indicating the response
        :rtype: :class:`splunklib.data.Record`
        """
        # Add output mode to body
        if "output_mode" not in body:
            body["output_mode"] = "json"

        # Query the content versioning service
        try:
            # TODO: The comment out section is for validating versioning is enabled and ready to go. The validation
            # workflow (whether to be part of wait_for_cms_main or a separate function) is planed to be implemented
            # in later contentctl-ng.
            # API endpoint for checking versioning status after ES 8.3.0
            # if method == "GET" and self.kvstore_content_versioning:
            #     response = self.service.request(
            #         method=method,
            #         path_segment="content_versioning/versioning_apps",
            #         app="SA-ContentVersioning",
            #     )
            # if self.indexbased_content_versioning:
            response = self.service.request(  # type: ignore
                method=method,
                path_segment="configs/conf-feature_flags/general",
                body=body,
                app="SA-ContentVersioning",
            )
        except HTTPError as e:
            # Raise on any HTTP errors
            raise HTTPError(f"Error querying content versioning service: {e}") from e

        return response

    @property
    def is_versioning_activated(self) -> bool:
        """
        Indicates whether the versioning service is activated or not

        :returns: a bool indicating if content versioning is activated or not
        :rtype: bool
        """
        # Query the SA-ContentVersioning service for versioning status
        response = self._query_content_versioning_service(method="GET")

        # Grab the response body and check for errors
        if "body" not in response:
            raise KeyError(
                f"Cannot retrieve versioning status, 'body' was not found in JSON response: {response}"
            )
        body: Any = response["body"]  # type: ignore
        if not isinstance(body, ResponseReader):
            raise ValueError(
                "Cannot retrieve versioning status, value at 'body' in JSON response had an unexpected"
                f" type: expected '{ResponseReader}', received '{type(body)}'"
            )

        # Read the JSON and parse it into a dictionary
        json_ = body.readall()
        try:
            data = json.loads(json_)
        except json.JSONDecodeError as e:
            raise ValueError(f"Unable to parse response body as JSON: {e}") from e

        # Find the versioning_activated field and report any errors
        try:
            # TODO: The comment out section is for validating versioning is enabled and ready to go. The validation
            # workflow (whether to be part of wait_for_cms_main or a separate function) is planed to be implemented
            # in later contentctl-ng.
            # Validating response by checking `status` field in `DA-ESS-ContentUpdate` app
            # if self.kvstore_content_versioning:
            #     if "content" in data:
            #         for app in data["content"]:
            #             if app.get("name") == "DA-ESS-ContentUpdate":
            #                 # If there is error message versioning is not activated properly
            #                 if "message" in app:
            #                     return False

            #                 # If the installed verion is not the same as the test version
            #                 if app.get("version") != self.global_config.app.version:
            #                     return False

            #                 if app.get("status") == "active":
            #                     return True
            #     else:
            #         return False
            # if self.indexbased_content_versioning:
            for entry in data["entry"]:
                if entry["name"] == "general":
                    return bool(int(entry["content"]["versioning_activated"]))
        except KeyError as e:
            raise KeyError(
                "Cannot retrieve versioning status, unable to determine versioning status using "
                f"the expected keys: {e}"
            ) from e
        raise ValueError(
            "Cannot retrieve versioning status, unable to find an entry matching 'general' in the "
            "response."
        )

    def activate_versioning(self) -> None:
        """
        Activate the content versioning service
        """
        # Post to the SA-ContentVersioning service to set versioning status
        self._query_content_versioning_service(
            method="POST", body={"versioning_activated": True}
        )

        # TODO: The comment out section is for validating versioning is enabled and ready to go. The validation
        # workflow (whether to be part of wait_for_cms_main or a separate function) is planed to be implemented
        # in later contentctl-ng.
        # The versioning is expected to be ready within 10 minutes
        # if self.kvstore_content_versioning:
        #     timeout = 600
        #     while not self.is_versioning_activated:
        #         time.sleep(60)
        #         timeout -= 60
        #         if timeout <= 0:
        #             break

        # Confirm versioning has been enabled
        if not self.is_versioning_activated:
            raise Exception(
                "Something went wrong, content versioning is still disabled."
            )

        self.logger.info(
            f"[{self.infrastructure.instance_name}] Versioning service successfully activated"
        )

    @property
    def is_cms_parser_enabled(self) -> bool:
        """
        Indicates whether the cms_parser mod input is enabled or not.

        :returns: a bool indicating if cms_parser mod input is activated or not
        :rtype: bool
        """
        # Get the data input entity
        cms_parser = self.service.input("data/inputs/cms_parser/main")  # type: ignore

        # Convert the 'disabled' field to an int, then a bool, and then invert to be 'enabled'
        return not bool(int(cms_parser.content["disabled"]))  # type: ignore

    def force_cms_parser(self) -> None:
        """
        Force the cms_parser to run by disabling and re-enabling it.
        """
        # Get the data input entity
        cms_parser = self.service.input("data/inputs/cms_parser/main")  # type: ignore

        # Disable and re-enable
        cms_parser.disable()
        cms_parser.enable()

        # Confirm the cms_parser is enabled
        if not self.is_cms_parser_enabled:
            raise Exception("Something went wrong, cms_parser is still disabled.")

        self.logger.info(
            f"[{self.infrastructure.instance_name}] cms_parser successfully toggled to force run"
        )

    def wait_for_cms_main(self) -> None:
        """
        Checks the cms_main index until it has the expected number of events, or it times out.
        """
        # Force the cms_parser to start parsing our savedsearches.conf
        self.force_cms_parser()

        # Set counters and limits for out exp. backoff timer
        elapsed_sleep_time = 0
        num_tries = 0
        time_to_sleep = 2**num_tries
        max_sleep = 600

        # Loop until timeout
        while elapsed_sleep_time < max_sleep:
            # Sleep, and add the time to the elapsed counter
            self.logger.info(
                f"[{self.infrastructure.instance_name}] Waiting {time_to_sleep} for cms_parser to "
                "finish"
            )
            time.sleep(time_to_sleep)
            elapsed_sleep_time += time_to_sleep
            self.logger.info(
                f"[{self.infrastructure.instance_name}] Checking cms_main (attempt #{num_tries + 1}"
                f" - {elapsed_sleep_time} seconds elapsed of {max_sleep} max)"
            )

            # Check if the number of CMS events matches or exceeds the number of detections
            if self.get_num_cms_events() >= len(self.detections):
                self.logger.info(
                    f"[{self.infrastructure.instance_name}] Found "
                    f"{self.get_num_cms_events(use_cache=True)} events in cms_main which "
                    f"meets or exceeds the expected {len(self.detections)}."
                )
                break
            else:
                self.logger.info(
                    f"[{self.infrastructure.instance_name}] Found "
                    f"{self.get_num_cms_events(use_cache=True)} matching events in cms_main;  "
                    f"expecting {len(self.detections)}. Continuing to wait..."
                )
            # Update the number of times we've tried, and increment the time to sleep
            num_tries += 1
            time_to_sleep = 2**num_tries

            # If the computed time to sleep will exceed max_sleep, adjust appropriately
            if (elapsed_sleep_time + time_to_sleep) > max_sleep:
                time_to_sleep = max_sleep - elapsed_sleep_time

    def _query_cms_main(self, use_cache: bool = False) -> splunklib.Job:
        """
        Queries the cms_main index, optionally appending the provided query suffix.

        :param use_cache: a flag indicating whether the cached job should be returned
        :type use_cache: bool

        :returns: a search Job entity
        :rtype: :class:`splunklib.client.Job`
        """
        # Use the cached job if asked to do so
        if use_cache:
            if self._cms_main_job is not None:
                return self._cms_main_job
            raise Exception(
                "Attempting to return a cached job against the cms_main index, but no job has been"
                " cached yet."
            )

        # Construct the query looking for CMS events matching the content app name
        if self.kvstore_content_versioning:
            query = (
                f"| inputlookup cms_content_lookup | search app_name={self.global_config.app.appid}"
                f"| fields content"
            )
        elif self.indexbased_content_versioning:
            query = (
                f"search index=cms_main sourcetype=stash_common_detection_model "
                f'app_name="{self.global_config.app.appid}" | fields _raw'
            )
        else:
            if self.kvstore_content_versioning:
                raise Exception(
                    f"Unable to perform search to cms_content_lookup in ES version {self.es_version}"
                )
            elif self.indexbased_content_versioning:
                raise Exception(
                    f"Unable to perform search to cms_main index in ES version {self.es_version}"
                )
            else:
                raise Exception(
                    f"Unable to determine content versioning method for ES version {self.es_version}. "
                    "Expected ES version >= 8.0.0."
                )
        self.logger.debug(
            f"[{self.infrastructure.instance_name}] Query on cms_main: {query}"
        )

        # Get the job as a blocking operation, set the cache, and return
        self._cms_main_job = self.service.search(query, exec_mode="blocking")  # type: ignore

        return self._cms_main_job

    def get_num_cms_events(self, use_cache: bool = False) -> int:
        """
        Gets the number of matching events in the cms_main index

        :param use_cache: a flag indicating whether the cached job should be returned
        :type use_cache: bool

        :returns: the count of matching events
        :rtype: int
        """
        # Query the cms_main index
        job = self._query_cms_main(use_cache=use_cache)

        # Convert the result count to an int
        return int(job["resultCount"])

    def validate_content_against_cms(self) -> None:
        """
        Using the cms_main index, validate content against the index to ensure our
        savedsearches.conf is compatible with ES content versioning features. **NOTE**: while in
        the future, this function may validate more types of content, currently, we only validate
        detections against the cms_main index.
        """
        # Get the cached job and result count
        result_count = self.get_num_cms_events(use_cache=True)
        job = self._query_cms_main(use_cache=True)

        # Create a running list of validation errors
        exceptions: list[Exception] = []

        # Generate an error for the count mismatch
        if result_count != len(self.detections):
            msg = (
                f"[{self.infrastructure.instance_name}] Expected {len(self.detections)} matching "
                f"events in cms_main, but found {result_count}."
            )
            self.logger.error(msg)
            exceptions.append(Exception(msg))
        self.logger.info(
            f"[{self.infrastructure.instance_name}] Expecting {len(self.detections)} matching "
            f"events in cms_main, found {result_count}."
        )

        # Init some counters and a mapping of detections to their names
        count = 100
        offset = 0
        remaining_detections = {
            x.get_action_dot_correlationsearch_dot_label(self.global_config.app): x
            for x in self.detections
        }
        matched_detections: dict[str, Detection] = {}

        # Create a filter for a specific memory error we're ok ignoring
        sub_second_order_pattern = re.compile(
            r".*Events might not be returned in sub-second order due to search memory limits.*"
        )

        # Iterate over the results until we've gone through them all
        while offset < result_count:
            iterator = ResultIterator(
                response_reader=job.results(  # type: ignore
                    output_mode="json", count=count, offset=offset
                ),
                error_filters=[sub_second_order_pattern],
            )

            # Iterate over the currently fetched results
            for cms_event in iterator:
                # Increment the offset for each result
                offset += 1

                if self.kvstore_content_versioning:
                    cms_event = CMSEvent(content=cms_event["content"])
                elif self.indexbased_content_versioning:
                    cms_event = CMSEvent(content=cms_event["_raw"])

                # Get the name of the search in the CMS event
                cms_entry_name = cms_event.action_correlationsearch_label
                self.logger.info(
                    f"[{self.infrastructure.instance_name}] {offset}: Matching cms_main entry "
                    f"'{cms_entry_name}' against detections"
                )

                # If CMS entry name matches one of the detections already matched, we've got an
                # unexpected repeated entry
                if cms_entry_name in matched_detections:
                    msg = (
                        f"[{self.infrastructure.instance_name}] [{cms_entry_name}]: Detection "
                        f"appears more than once in the cms_main index."
                    )
                    self.logger.error(msg)
                    exceptions.append(Exception(msg))
                    continue

                # Iterate over the detections and compare the CMS entry name against each
                result_matches_detection = False
                for detection_cs_label in remaining_detections:
                    # If we find a match, break this loop, set the found flag and move the detection
                    # from those that still need to matched to those already matched
                    if cms_entry_name == detection_cs_label:
                        self.logger.info(
                            f"[{self.infrastructure.instance_name}] {offset}: Succesfully matched "
                            f"cms_main entry against detection ('{detection_cs_label}')!"
                        )

                        # Validate other fields of the cms_event against the detection
                        exception = self.validate_detection_against_cms_event(
                            cms_event, remaining_detections[detection_cs_label]
                        )

                        # Save the exception if validation failed
                        if exception is not None:
                            exceptions.append(exception)

                        # Delete the matched detection and move it to the matched list
                        result_matches_detection = True
                        matched_detections[detection_cs_label] = remaining_detections[
                            detection_cs_label
                        ]
                        del remaining_detections[detection_cs_label]
                        break

                # Generate an exception if we couldn't match the CMS main entry to a detection
                if result_matches_detection is False:
                    msg = (
                        f"[{self.infrastructure.instance_name}] [{cms_entry_name}]: Could not "
                        "match entry in cms_main against any of the expected detections."
                    )
                    self.logger.error(msg)
                    exceptions.append(Exception(msg))

        # If we have any remaining detections, they could not be matched against an entry in
        # cms_main and there may have been a parsing issue with savedsearches.conf
        if len(remaining_detections) > 0:
            # Generate exceptions for the unmatched detections
            for detection_cs_label in remaining_detections:
                msg = (
                    f"[{self.infrastructure.instance_name}] [{detection_cs_label}]: Detection not "
                    "found in cms_main; there may be an issue with savedsearches.conf"
                )
                self.logger.error(msg)
                exceptions.append(Exception(msg))

        # Raise exceptions as a group
        if len(exceptions) > 0:
            raise ExceptionGroup(
                "1 or more issues validating our detections against the cms_main index",
                exceptions,
            )

        # Else, we've matched/validated all detections against cms_main
        self.logger.info(
            f"[{self.infrastructure.instance_name}] Matched and validated all detections against "
            "cms_main!"
        )

    def validate_detection_against_cms_event(
        self, cms_event: CMSEvent, detection: Detection
    ) -> Exception | None:
        """
        Given an event from the cms_main index and the matched detection, compare fields and look
        for any inconsistencies

        :param cms_event: The event from the cms_main index
        :type cms_event: CMSEvent
        :param detection: The matched detection
        :type detection: :class:`contentctl.objects.detection.Detection`

        :return: The generated exception, or None
        :rtype: Exception | None
        """
        # TODO (PEX-509): validate additional fields between the cms_event and the detection

        cms_uuid = uuid.UUID(cms_event.detection_id)
        rule_name_from_detection = detection.get_action_dot_correlationsearch_dot_label(
            self.global_config.app
        )

        cms_entry_name = cms_event.action_correlationsearch_label

        # Compare the correlation search label
        if cms_entry_name != rule_name_from_detection:
            msg = (
                f"[{self.infrastructure.instance_name}][{detection.name}]: Correlation search "
                f"label in cms_event ('{cms_entry_name}') does not match detection name"
            )
            self.logger.error(msg)
            return Exception(msg)
        elif cms_uuid != detection.id:
            # Compare the UUIDs
            msg = (
                f"[{self.infrastructure.instance_name}] [{detection.name}]: UUID in cms_event "
                f"('{cms_uuid}') does not match UUID in detection ('{detection.id}')"
            )
            self.logger.error(msg)
            return Exception(msg)
        elif cms_event.version != f"{detection.version}.1":
            # Compare the versions (we append '.1' to the detection version to be in line w/ the
            # internal representation in ES)
            msg = (
                f"[{self.infrastructure.instance_name}] [{detection.name}]: Version in cms_event "
                f"('{cms_event.version}') does not match version in detection "
                f"('{detection.version}.1')"
            )
            self.logger.error(msg)
            return Exception(msg)

        return None
