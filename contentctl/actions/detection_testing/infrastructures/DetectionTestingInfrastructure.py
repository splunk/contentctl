import time
import uuid
import abc
import os.path
import configparser
import json
import datetime
import tqdm
import pathlib
from tempfile import TemporaryDirectory, mktemp
from ssl import SSLEOFError, SSLZeroReturnError
from sys import stdout
from dataclasses import dataclass
from shutil import copyfile
from typing import Union
from enum import Enum

from pydantic import BaseModel, PrivateAttr, Field
import requests
import splunklib.client as client
from splunklib.binding import HTTPError
from splunklib.results import JSONResultsReader, Message
import splunklib.results
from urllib3 import disable_warnings
import urllib.parse

from contentctl.objects.enums import PostTestBehavior, DetectionStatus
from contentctl.objects.detection import Detection
from contentctl.objects.unit_test import UnitTest
from contentctl.objects.unit_test_attack_data import UnitTestAttackData
from contentctl.objects.unit_test_result import UnitTestResult
from contentctl.objects.integration_test import IntegrationTest
from contentctl.objects.integration_test_result import IntegrationTestResult
from contentctl.objects.test_config import TestConfig, Infrastructure
from contentctl.objects.test_group import TestGroup
from contentctl.objects.base_test_result import TestResultStatus
from contentctl.helper.utils import Utils
from contentctl.actions.detection_testing.DataManipulation import (
    DataManipulation,
)


class TestReportingType(str, Enum):
    """
    5-char identifiers for the type of testing being reported on
    """
    # Reporting around general testing setup (e.g. infra, role configuration)
    SETUP = "SETUP"

    # Reporting around a group of tests
    GROUP = "GROUP"

    # Reporting around a unit test
    UNIT = "UNIT "

    # Reporting around an integration test
    INTEGRATION = "INTEG"


class TestingStates(str, Enum):
    """
    Defined testing states
    """
    BEGINNING_GROUP = "Beginning Test Group"
    BEGINNING_TEST = "Beginning Test"
    DOWNLOADING = "Downloading Data"
    REPLAYING = "Replaying Data"
    PROCESSING = "Waiting for Processing"
    SEARCHING = "Running Search"
    DELETING = "Deleting Data"
    DONE_GROUP = "Test Group Done"


# the longest length of any state
LONGEST_STATE = max(len(w.value) for w in TestingStates)


class FinalTestingStates(str, Enum):
    """
    The possible final states for a test (for pbar reporting)
    """
    FAIL = "\x1b[0;30;41m" + "FAIL".ljust(LONGEST_STATE) + "\x1b[0m"
    PASS = "\x1b[0;30;42m" + "PASS".ljust(LONGEST_STATE) + "\x1b[0m"
    SKIP = "\x1b[0;30;47m" + "SKIP".ljust(LONGEST_STATE) + "\x1b[0m"


# max length of a test name
# TODO: this max size is declared, and it is used appropriatel w/ .ljust, but nothing truncates test names to makes 
#   them the appropriate size
MAX_TEST_NAME_LENGTH = 70

# The format string used for pbar reporting
PBAR_FORMAT_STRING = "[{test_reporting_type}] {test_name} >> {state} | Time: {time}"


class SetupTestGroupResults(BaseModel):
    exception: Union[Exception, None] = None
    success: bool = True
    duration: float = 0
    start_time: float

    class Config:
        arbitrary_types_allowed = True


class CleanupTestGroupResults(BaseModel):
    duration: float
    start_time: float


class ContainerStoppedException(Exception):
    pass


@dataclass(frozen=False)
class DetectionTestingManagerOutputDto:
    inputQueue: list[Detection] = Field(default_factory=list)
    outputQueue: list[Detection] = Field(default_factory=list)
    skippedQueue: list[Detection] = Field(default_factory=list)
    currentTestingQueue: dict[str, Union[Detection, None]] = Field(default_factory=dict)
    start_time: Union[datetime.datetime, None] = None
    replay_index: str = "CONTENTCTL_TESTING_INDEX"
    replay_host: str = "CONTENTCTL_HOST"
    timeout_seconds: int = 60
    terminate: bool = False


class DetectionTestingInfrastructure(BaseModel, abc.ABC):
    # thread: threading.Thread = threading.Thread()
    global_config: TestConfig
    infrastructure: Infrastructure
    sync_obj: DetectionTestingManagerOutputDto
    hec_token: str = ""
    hec_channel: str = ""
    _conn: client.Service = PrivateAttr()
    pbar: tqdm.tqdm = None
    start_time: float = None

    class Config:
        arbitrary_types_allowed = True

    def __init__(self, **data):
        super().__init__(**data)

    def start(self):
        raise (
            NotImplementedError(
                "start() is not implemented for Abstract Type DetectionTestingInfrastructure"
            )
        )

    def get_name(self) -> str:
        raise (
            NotImplementedError(
                "get_name() is not implemented for Abstract Type DetectionTestingInfrastructure"
            )
        )

    def setup(self):
        self.pbar = tqdm.tqdm(
            total=100,
            initial=0,
            bar_format=f"{self.get_name()} starting",
            miniters=0,
            mininterval=0,
            file=stdout
        )

        self.start_time = time.time()
        try:
            for func, msg in [
                (self.start, "Starting"),
                (self.get_conn, "Waiting for App Installation"),
                (self.configure_conf_file_datamodels, "Configuring Datamodels"),
                (self.create_replay_index, f"Create index '{self.sync_obj.replay_index}'"),
                (self.configure_imported_roles, "Configuring Roles"),
                (self.configure_delete_indexes, "Configuring Indexes"),
                (self.configure_hec, "Configuring HEC"),
                (self.wait_for_ui_ready, "Finishing Setup")
            ]:

                self.format_pbar_string(
                    TestReportingType.SETUP,
                    self.get_name(),
                    msg,
                    self.start_time,
                    update_sync_status=True,
                )
                func()
                self.check_for_teardown()

        except Exception as e:
            self.pbar.write(str(e))
            self.finish()
            return

        self.format_pbar_string(TestReportingType.SETUP, self.get_name(), "Finished Setup!", self.start_time)

    def wait_for_ui_ready(self):
        self.get_conn()

    def configure_hec(self):
        self.hec_channel = str(uuid.uuid4())
        try:
            res = self.get_conn().input(
                path="/servicesNS/nobody/splunk_httpinput/data/inputs/http/http:%2F%2FDETECTION_TESTING_HEC"
            )
            self.hec_token = str(res.token)
            return
        except Exception:
            # HEC input does not exist.  That's okay, we will create it
            pass

        try:

            res = self.get_conn().inputs.create(
                name="DETECTION_TESTING_HEC",
                kind="http",
                index=self.sync_obj.replay_index,
                indexes=f"{self.sync_obj.replay_index},_internal,_audit",
                useACK=True,
            )
            self.hec_token = str(res.token)
            return

        except Exception as e:
            raise (Exception(f"Failure creating HEC Endpoint: {str(e)}"))

    def get_conn(self) -> client.Service:
        try:
            if not self._conn:
                self.connect_to_api()
            elif self._conn.restart_required:
                # continue trying to re-establish a connection until after
                # the server has restarted
                self.connect_to_api()
        except Exception:
            # there was some issue getting the connection. Try again just once
            self.connect_to_api()
        return self._conn

    def check_for_teardown(self):
        # Make sure we can easily quit during setup if we need to.
        # Some of these stages can take a long time
        if self.sync_obj.terminate:
            # Exiting in a thread just quits the thread, not the entire process
            raise (ContainerStoppedException(f"Testing stopped for {self.get_name()}"))

    def connect_to_api(self, sleep_seconds: int = 5):
        while True:
            self.check_for_teardown()
            try:

                conn = client.connect(
                    host=self.infrastructure.instance_address,
                    port=self.infrastructure.api_port,
                    username=self.infrastructure.splunk_app_username,
                    password=self.infrastructure.splunk_app_password,
                )

                if conn.restart_required:
                    self.format_pbar_string(
                        TestReportingType.SETUP,
                        self.get_name(),
                        "Waiting for reboot",
                        self.start_time,
                        update_sync_status=True,
                    )
                else:
                    # Finished setup
                    self._conn = conn
                    return

            except ConnectionRefusedError as e:
                raise (e)
            except SSLEOFError:
                pass
            except SSLZeroReturnError:
                pass
            except ConnectionResetError:
                pass
            except Exception as e:
                self.pbar.write(
                    f"Error getting API connection (not quitting) '{type(e).__name__}': {str(e)}"
                )
                # self.pbar.write(
                #     f"Unhandled exception getting connection to splunk server: {str(e)}"
                # )
                # self.sync_obj.terminate = True

            for _ in range(sleep_seconds):
                self.format_pbar_string(
                    TestReportingType.SETUP,
                    self.get_name(),
                    "Getting API Connection",
                    self.start_time,
                    update_sync_status=True,
                )
                time.sleep(1)

    def create_replay_index(self):

        try:
            self.get_conn().indexes.create(name=self.sync_obj.replay_index)
        except HTTPError as e:
            if b"already exists" in e.body:
                pass
            else:
                raise Exception(
                    f"Error creating index {self.sync_obj.replay_index} - {str(e)}"
                )

    def configure_imported_roles(
        self,
        imported_roles: list[str] = ["user", "power", "can_delete"],
        enterprise_security_roles: list[str] = ["ess_admin", "ess_analyst", "ess_user"],
        indexes: list[str] = ["_*", "*"],
    ):
        indexes.append(self.sync_obj.replay_index)
        indexes_encoded = ";".join(indexes)
        try:
            self.get_conn().roles.post(
                self.infrastructure.splunk_app_username,
                imported_roles=imported_roles + enterprise_security_roles,
                srchIndexesAllowed=indexes_encoded,
                srchIndexesDefault=self.sync_obj.replay_index,
            )
            return
        except Exception as e:
            self.pbar.write(
                f"Enterprise Security Roles do not exist:'{enterprise_security_roles}: {str(e)}"
            )

        self.get_conn().roles.post(
            self.infrastructure.splunk_app_username,
            imported_roles=imported_roles,
            srchIndexesAllowed=indexes_encoded,
            srchIndexesDefault=self.sync_obj.replay_index,
        )

    def configure_delete_indexes(self, indexes: list[str] = ["_*", "*"]):
        indexes.append(self.sync_obj.replay_index)
        endpoint = "/services/properties/authorize/default/deleteIndexesAllowed"
        indexes_encoded = ";".join(indexes)
        try:
            self.get_conn().post(endpoint, value=indexes_encoded)
        except Exception as e:
            self.pbar.write(
                f"Error configuring deleteIndexesAllowed with '{indexes_encoded}': [{str(e)}]"
            )

    def wait_for_conf_file(self, app_name: str, conf_file_name: str):
        while True:
            self.check_for_teardown()
            time.sleep(1)
            try:
                _ = self.get_conn().get(
                    f"configs/conf-{conf_file_name}", app=app_name
                )
                return
            except Exception:
                pass
                self.format_pbar_string(
                    TestReportingType.SETUP,
                    self.get_name(),
                    "Configuring Datamodels",
                    self.start_time,
                )

    def configure_conf_file_datamodels(self, APP_NAME: str = "Splunk_SA_CIM"):
        self.wait_for_conf_file(APP_NAME, "datamodels")

        parser = configparser.ConfigParser()
        cim_acceleration_datamodels = pathlib.Path(
            os.path.join(
                os.path.dirname(__file__), "../../../templates/datamodels_cim.conf"
            )
        )

        custom_acceleration_datamodels = pathlib.Path(
            os.path.join(
                os.path.dirname(__file__), "../../../templates/datamodels_custom.conf"
            )
        )

        if custom_acceleration_datamodels.is_file():
            parser.read(custom_acceleration_datamodels)
            if len(parser.keys()) > 1:
                self.pbar.write(
                    f"Read {len(parser)-1} custom datamodels from {str(custom_acceleration_datamodels)}!"
                )

        if not cim_acceleration_datamodels.is_file():
            self.pbar.write(
                f"******************************\nDATAMODEL ACCELERATION FILE {str(cim_acceleration_datamodels)} NOT "
                "FOUND. CIM DATAMODELS NOT ACCELERATED\n******************************\n"
            )
        else:
            parser.read(cim_acceleration_datamodels)

        for datamodel_name in parser:
            if datamodel_name == "DEFAULT":
                # Skip the DEFAULT section for configparser
                continue
            for name, value in parser[datamodel_name].items():
                try:
                    _ = self.get_conn().post(
                        f"properties/datamodels/{datamodel_name}/{name}",
                        app=APP_NAME,
                        value=value,
                    )

                except Exception as e:
                    self.pbar.write(
                        f"Error creating the conf Datamodel {datamodel_name} key/value {name}/{value}: {str(e)}"
                    )

    def execute(self):
        while True:
            try:
                self.check_for_teardown()
            except ContainerStoppedException:
                self.finish()
                return

            try:
                detection = self.sync_obj.inputQueue.pop()
                if detection.status != DetectionStatus.production.value:
                    # NOTE: we handle skipping entire detections differently than we do skipping individual test cases;
                    #   we skip entire detections by excluding them to an entirely separate queue, while we skip 
                    #   individual test cases via the BaseTest.skip() method, such as when we are skipping all 
                    #   integration tests (see DetectionBuilder.skipIntegrationTests)
                    self.sync_obj.skippedQueue.append(detection)
                    self.pbar.write(f"\nSkipping {detection.name} since it is status: {detection.status}\n")
                    continue
                self.sync_obj.currentTestingQueue[self.get_name()] = detection
            except IndexError:
                # self.pbar.write(
                #    f"No more detections to test, shutting down {self.get_name()}"
                # )
                self.finish()
                return
            try:
                self.test_detection(detection)
            except ContainerStoppedException:
                self.pbar.write(f"Stopped container [{self.get_name()}]")
                self.finish()
                return
            except Exception as e:
                self.pbar.write(f"Error testing detection: {type(e).__name__}: {str(e)}")
            finally:
                self.sync_obj.outputQueue.append(detection)
                self.sync_obj.currentTestingQueue[self.get_name()] = None

    def test_detection(self, detection: Detection):
        if detection.tests is None:
            self.pbar.write(f"No test(s) found for {detection.name}")
            return

        # iterate TestGroups
        for test_group in detection.test_groups:
            test_group.unit_test.skip("skip")
            # If all tests in the group have been skipped, report and continue
            if test_group.all_tests_skipped():
                self.pbar.write(
                    self.format_pbar_string(
                        TestReportingType.GROUP,
                        test_group.name,
                        FinalTestingStates.SKIP.value,
                        time.time(),
                        set_pbar=False,
                    )
                )
                continue

            # replay attack_data
            setup_results = self.setup_test_group(test_group)

            # TODO: make it clear to Eric that test durations will no longer account for
            # replay/cleanup in this new test grouping model (in the CLI reporting; the recorded
            # test duration in the result file will include the setup/cleanup time in the duration
            # for both unit and integration tests (effectively double counted))

            # run unit test
            self.execute_unit_test(detection, test_group.unit_test, setup_results)

            # run integration test
            self.execute_integration_test(
                detection,
                test_group.integration_test,
                setup_results
            )

            # cleanup
            cleanup_results = self.cleanup_test_group(test_group, setup_results.start_time)

            # update the results duration w/ the setup/cleanup time (for those not skipped)
            if (test_group.unit_test.result is not None) and (not test_group.unit_test_skipped()):
                test_group.unit_test.result.duration = round(
                    test_group.unit_test.result.duration + setup_results.duration + cleanup_results.duration,
                    2
                )
            if (test_group.integration_test.result is not None) and (not test_group.integration_test_skipped()):
                test_group.integration_test.result.duration = round(
                    test_group.integration_test.result.duration + setup_results.duration + cleanup_results.duration,
                    2
                )

            self.pbar.write(f"unit_test.duration: {test_group.unit_test.result.duration}")
            self.pbar.write(f"integration_test.duration: {test_group.integration_test.result.duration}")
            self.pbar.write(f"setup_results.duration: {setup_results.duration}")
            self.pbar.write(f"cleanup_results.duration: {cleanup_results.duration}")

            # Write test group status
            self.pbar.write(
                self.format_pbar_string(
                    TestReportingType.GROUP,
                    test_group.name,
                    TestingStates.DONE_GROUP.value,
                    setup_results.start_time,
                    set_pbar=False,
                )
            )

    def setup_test_group(self, test_group: TestGroup) -> SetupTestGroupResults:
        """
        Executes attack_data replay, captures test group start time, does some reporting to the CLI
        and returns an object encapsulating the results of data replay
        :param test_group: the TestGroup to replay for
        :returns: SetupTestGroupResults
        """
        # Capture the setup start time
        setup_start_time = time.time()
        self.pbar.write(f"setup_start_time: {setup_start_time}")
        self.pbar.reset()
        self.format_pbar_string(
            TestReportingType.GROUP,
            test_group.name,
            TestingStates.BEGINNING_GROUP.value,
            setup_start_time
        )
        # https://github.com/WoLpH/python-progressbar/issues/164
        # Use NullBar if there is more than 1 container or we are running
        # in a non-interactive context

        results = SetupTestGroupResults(start_time=setup_start_time)

        try:
            self.replay_attack_data_files(test_group, setup_start_time)
        except Exception as e:
            results.exception = e
            results.success = False

        results.duration = time.time() - setup_start_time
        return results

    def cleanup_test_group(
            self,
            test_group: TestGroup,
            test_group_start_time: float
    ) -> CleanupTestGroupResults:
        cleanup_start_time = time.time()
        self.format_pbar_string(
            TestReportingType.GROUP,
            test_group.name,
            TestingStates.DELETING.value,
            test_group_start_time,
        )

        # TODO: do we want to clean up even if replay failed? Could have been partial failure?
        self.delete_attack_data(test_group.attack_data)

        return CleanupTestGroupResults(
            duration=time.time() - cleanup_start_time,
            start_time=cleanup_start_time
        )

    def format_pbar_string(
        self,
        test_reporting_type: TestReportingType,
        test_name: str,
        state: str,
        start_time: Union[float, None],
        set_pbar: bool = True,
        update_sync_status: bool = False,
    ) -> str:
        if start_time is None:
            start_time = self.start_time
        field_one = test_reporting_type.value
        field_two = test_name.ljust(MAX_TEST_NAME_LENGTH)
        field_three = state.ljust(LONGEST_STATE)
        field_four = datetime.timedelta(seconds=round(time.time() - start_time))
        new_string = PBAR_FORMAT_STRING.format(
            test_reporting_type=field_one,
            test_name=field_two,
            state=field_three,
            time=field_four,
        )
        if set_pbar:
            self.pbar.bar_format = new_string
            self.pbar.update()
        if update_sync_status:
            self.sync_obj.currentTestingQueue[self.get_name()] = {
                "name": state,
                "search": "N/A",
            }
        return new_string

    def execute_unit_test(
        self,
        detection: Detection,
        test: UnitTest,
        setup_results: SetupTestGroupResults,
        FORCE_ALL_TIME: bool = True
    ):
        """
        Execute a unit test and set its results appropriately
        :param detection: the detection being tested
        :param test: the specific test case (UnitTest)
        :param setup_results: the results of test group setup
        :param FORCE_ALL_TIME: boolean flag; if True, searches check data for all time; if False,
            any earliest_time or latest_time configured in the test is respected
        """
        # Capture unit test start time
        test_start_time = time.time()

        # First, check to see if this test has been skipped; log and return if so
        if test.result is not None and test.result.status == TestResultStatus.SKIP:
            # report the skip to the CLI
            self.pbar.write(
                self.format_pbar_string(
                    TestReportingType.UNIT,
                    f"{detection.name}:{test.name}",
                    FinalTestingStates.SKIP.value,
                    start_time=test_start_time,
                    set_pbar=False,
                )
            )
            return

        # Reset the pbar and print that we are beginning a unit test
        self.pbar.reset()
        self.format_pbar_string(
            TestReportingType.UNIT,
            f"{detection.name}:{test.name}",
            TestingStates.BEGINNING_TEST,
            test_start_time,
        )

        # if the replay failed, record the test failure and return
        if not setup_results.success:
            test.result = UnitTestResult()
            test.result.set_job_content(
                None,
                self.infrastructure,
                exception=setup_results.exception,
                duration=round(time.time() - test_start_time, 2)
            )

            # report the failure to the CLI
            self.pbar.write(
                self.format_pbar_string(
                    TestReportingType.UNIT,
                    f"{detection.name}:{test.name}",
                    FinalTestingStates.FAIL.value,
                    start_time=test_start_time,
                    set_pbar=False,
                )
            )

            return

        # Set the mode and timeframe, if required
        kwargs = {"exec_mode": "blocking"}

        # Iterate over baselines (if any)
        for baseline in test.baselines:
            # TODO: this is executing the test, not the baseline...
            # TODO: should this be in a try/except if the later call is?
            self.retry_search_until_timeout(detection, test, kwargs, test_start_time)

        # Set earliest_time and latest_time appropriately if FORCE_ALL_TIME is False
        if not FORCE_ALL_TIME:
            if test.earliest_time is not None:
                kwargs.update({"earliest_time": test.earliest_time})
            if test.latest_time is not None:
                kwargs.update({"latest_time": test.latest_time})

        # Run the detection's search query
        try:
            self.retry_search_until_timeout(detection, test, kwargs, test_start_time)
        except ContainerStoppedException as e:
            raise e
        except Exception as e:
            # Init the test result and record a failure if there was an issue during the search
            test.result = UnitTestResult()
            test.result.set_job_content(
                None, self.infrastructure, exception=e, duration=time.time() - test_start_time
            )

        # Pause here if the terminate flag has NOT been set AND either of the below are true:
        #   1. the behavior is always_pause
        #   2. the behavior is pause_on_failure and the test failed
        if (
            self.global_config.post_test_behavior == PostTestBehavior.always_pause
            or (
                self.global_config.post_test_behavior == PostTestBehavior.pause_on_failure
                and (test.result is None or test.result.success is False)
            )
        ) and not self.sync_obj.terminate:
            # Determine the state to report to the user
            if test.result is None:
                res = "ERROR"
                link = detection.search
            else:
                res = test.result.success
                if res:
                    res = "PASS"
                else:
                    res = "FAIL"
                link = test.result.get_summary_dict()["sid_link"]

            self.format_pbar_string(
                TestReportingType.UNIT,
                f"{detection.name}:{test.name}",
                f"{res} - {link} (CTRL+D to continue)",
                test_start_time,
            )

            # Wait for user input
            try:
                _ = input()
            except Exception:
                pass

        if test.result is not None and test.result.success:
            self.pbar.write(
                self.format_pbar_string(
                    TestReportingType.UNIT,
                    f"{detection.name}:{test.name}",
                    FinalTestingStates.PASS.value,
                    test_start_time,
                    set_pbar=False,
                )
            )

        else:
            self.pbar.write(
                self.format_pbar_string(
                    TestReportingType.UNIT,
                    f"{detection.name}:{test.name}",
                    FinalTestingStates.FAIL.value,
                    test_start_time,
                    set_pbar=False,
                )
            )
        stdout.flush()
        if test.result is not None:
            test.result.duration = round(time.time() - test_start_time, 2)

    def execute_integration_test(
        self,
        detection: Detection,
        test: IntegrationTest,
        setup_results: SetupTestGroupResults,
        FORCE_ALL_TIME: bool = True
    ):
        """
        Executes an integration test on the detection
        :param detection: the detection on which to run the test
        """
        # Capture unit test start time
        test_start_time = time.time()

        # First, check to see if this test has been skipped; log and return if so
        if test.result is not None and test.result.status == TestResultStatus.SKIP:
            # report the skip to the CLI
            self.pbar.write(
                self.format_pbar_string(
                    TestReportingType.INTEGRATION,
                    f"{detection.name}:{test.name}",
                    FinalTestingStates.SKIP.value,
                    start_time=test_start_time,
                    set_pbar=False,
                )
            )
            return

        # Reset the pbar and print that we are beginning a unit test
        self.pbar.reset()
        self.format_pbar_string(
            TestReportingType.INTEGRATION,
            f"{detection.name}:{test.name}",
            TestingStates.BEGINNING_TEST,
            test_start_time,
        )

        try:
            raise NotImplementedError
        except NotImplementedError:
            test.result = IntegrationTestResult()
            test.result.success = False

        # Pause here if the terminate flag has NOT been set AND either of the below are true:
        #   1. the behavior is always_pause
        #   2. the behavior is pause_on_failure and the test failed
        if (
            self.global_config.post_test_behavior == PostTestBehavior.always_pause
            or (
                self.global_config.post_test_behavior == PostTestBehavior.pause_on_failure
                and (test.result is None or test.result.success is False)
            )
        ) and not self.sync_obj.terminate:
            # Determine the state to report to the user
            if test.result is None:
                res = "ERROR"
                # link = detection.search
            else:
                res = test.result.success
                if res:
                    res = "PASS"
                else:
                    res = "FAIL"
                # link = test.result.get_summary_dict()["sid_link"]

            self.format_pbar_string(
                TestReportingType.INTEGRATION,
                f"{detection.name}:{test.name}",
                f"{res} (CTRL+D to continue)",
                test_start_time,
            )

            # Wait for user input
            try:
                _ = input()
            except Exception:
                pass

        if test.result is not None and test.result.success:
            self.pbar.write(
                self.format_pbar_string(
                    TestReportingType.INTEGRATION,
                    f"{detection.name}:{test.name}",
                    FinalTestingStates.PASS.value,
                    start_time=test_start_time,
                    set_pbar=False,
                )
            )
        else:
            # report the failure to the CLI
            self.pbar.write(
                self.format_pbar_string(
                    TestReportingType.INTEGRATION,
                    f"{detection.name}:{test.name}",
                    FinalTestingStates.FAIL.value,
                    start_time=test_start_time,
                    set_pbar=False,
                )
            )

    def retry_search_until_timeout(
        self,
        detection: Detection,
        test: UnitTest,
        kwargs: dict,
        start_time: float,
    ):
        """
        Retries a search until the timeout is reached, setting test results appropriately
        :param detection: the detection being tested
        :param test: the UnitTest case being tested
        :param kwargs: any additional keyword args to be passed with the search
        :param start_time: the start time of the caller
        """
        # Get the start time and compute the timeout
        search_start_time = time.time()
        search_stop_time = time.time() + self.sync_obj.timeout_seconds

        # We will default to ensuring at least one result exists
        if test.pass_condition is None:
            search = detection.search
        else:
            # Else, use the explicit pass condition
            search = f"{detection.search} {test.pass_condition}"

        # Ensure searches that do not begin with '|' must begin with 'search '
        if not search.strip().startswith("|"):
            if not search.strip().startswith("search "):
                search = f"search {search}"

        # exponential backoff for wait time
        tick = 2

        # Retry until timeout
        while time.time() < search_stop_time:

            # This loop allows us to capture shutdown events without being
            # stuck in an extended sleep. Remember that this raises an exception
            for _ in range(pow(2, tick - 1)):
                self.check_for_teardown()
                self.format_pbar_string(
                    TestReportingType.UNIT,
                    f"{detection.name}:{test.name}",
                    TestingStates.PROCESSING.value,
                    start_time
                )

                time.sleep(1)

            self.format_pbar_string(
                TestReportingType.UNIT,
                f"{detection.name}:{test.name}",
                TestingStates.SEARCHING.value,
                start_time,
            )

            # Execute the search and read the results
            job = self.get_conn().search(query=search, **kwargs)
            results = JSONResultsReader(job.results(output_mode="json"))

            # Consolidate a set of the distinct observable field names
            observable_fields_set = set([o.name for o in detection.tags.observable])

            # Ensure the search had at least one result
            if int(job.content.get("resultCount", "0")) > 0:
                # Initialize the test result
                test.result = UnitTestResult()

                # Initialize the collection of fields that are empty that shouldn't be
                empty_fields = set()

                # Filter out any messages in the results
                for result in results:
                    if isinstance(result, Message):
                        continue

                    # If not a message, it is a dict and we will process it
                    results_fields_set = set(result.keys())

                    # Identify any observable fields that are not available in the results
                    missing_fields = observable_fields_set - results_fields_set
                    if len(missing_fields) > 0:
                        # Report a failure in such cases
                        e = Exception(f"The observable field(s) {missing_fields} are missing in the detection results")
                        test.result.set_job_content(
                            job.content,
                            self.infrastructure,
                            exception=e,
                            success=False,
                            duration=time.time() - search_start_time,
                            )

                        return

                    # If we find one or more fields that contain the string "null" then they were
                    # not populated and we should throw an error.  This can happen if there is a typo
                    # on a field.  In this case, the field will appear but will not contain any values
                    current_empty_fields = set()
                    for field in observable_fields_set:
                        if result.get(field, 'null') == 'null':
                            current_empty_fields.add(field)

                    # If everything succeeded up until now, and no empty fields are found in the
                    # current result, then the search was a success
                    if len(current_empty_fields) == 0:
                        test.result.set_job_content(
                            job.content,
                            self.infrastructure,
                            success=True,
                            duration=time.time() - search_start_time,
                        )
                        self.pbar.write(f"runDuration: {test.result.job_content.runDuration}")
                        return

                    else:
                        empty_fields = empty_fields.union(current_empty_fields)

                # Report a failure if there were empty fields in all results
                e = Exception(
                    f"One or more required observable fields {empty_fields} contained 'null' values.  Is the "
                    "data being parsed correctly or is there an error in the naming of a field?"
                    )
                test.result.set_job_content(
                    job.content,
                    self.infrastructure,
                    exception=e,
                    success=False,
                    duration=time.time() - search_start_time,
                )

                return

            else:
                # Report a failure if there were no results at all
                test.result = UnitTestResult()
                test.result.set_job_content(
                    job.content,
                    self.infrastructure,
                    success=False,
                    duration=time.time() - search_start_time,
                )
                tick += 1

        return

    def delete_attack_data(self, attack_data_files: list[UnitTestAttackData]):
        for attack_data_file in attack_data_files:
            index = attack_data_file.custom_index or self.sync_obj.replay_index
            host = attack_data_file.host or self.sync_obj.replay_host
            splunk_search = f'search index="{index}" host="{host}" | delete'
            kwargs = {"exec_mode": "blocking"}
            try:

                job = self.get_conn().jobs.create(splunk_search, **kwargs)
                results_stream = job.results(output_mode="json")
                # TODO: should we be doing something w/ this reader?
                _ = splunklib.results.JSONResultsReader(results_stream)

            except Exception as e:
                raise (
                    Exception(
                        f"Trouble deleting data using the search {splunk_search}: {str(e)}"
                    )
                )

    def replay_attack_data_files(
        self,
        test_group: TestGroup,
        test_group_start_time: float,
    ):
        with TemporaryDirectory(prefix="contentctl_attack_data") as attack_data_dir:
            for attack_data_file in test_group.attack_data:
                self.replay_attack_data_file(
                    attack_data_file, attack_data_dir, test_group, test_group_start_time
                )

    def replay_attack_data_file(
        self,
        attack_data_file: UnitTestAttackData,
        tmp_dir: str,
        test_group: TestGroup,
        test_group_start_time: float,
    ):
        tempfile = mktemp(dir=tmp_dir)

        if not (
            attack_data_file.data.startswith("https://")
            or attack_data_file.data.startswith("http://")
        ):
            if pathlib.Path(attack_data_file.data).is_file():
                self.format_pbar_string(TestReportingType.GROUP, test_group.name, "Copying Data", test_group_start_time)
                try:
                    copyfile(attack_data_file.data, tempfile)
                except Exception as e:
                    raise Exception(
                        f"Error copying local Attack Data File for [{Detection.name}] - [{attack_data_file.data}]: "
                        f"{str(e)}"
                    )
            else:
                raise Exception(
                    f"Attack Data File for [{Detection.name}] is local [{attack_data_file.data}], but does not exist."
                )

        else:
            # Download the file
            # We need to overwrite the file - mkstemp will create an empty file with the
            # given name
            try:
                # In case the path is a local file, try to get it

                self.format_pbar_string(
                    TestReportingType.GROUP,
                    test_group.name,
                    TestingStates.DOWNLOADING.value,
                    test_group_start_time
                )

                Utils.download_file_from_http(
                    attack_data_file.data, tempfile, self.pbar, overwrite_file=True
                )
            except Exception as e:
                raise (
                    Exception(
                        f"Could not download attack data file [{attack_data_file.data}]:{str(e)}"
                    )
                )

        # Update timestamps before replay
        if attack_data_file.update_timestamp:
            data_manipulation = DataManipulation()
            data_manipulation.manipulate_timestamp(
                tempfile, attack_data_file.sourcetype, attack_data_file.source
            )

        # Upload the data
        self.format_pbar_string(
            TestReportingType.GROUP,
            test_group.name,
            TestingStates.REPLAYING.value,
            test_group_start_time
        )

        self.hec_raw_replay(tempfile, attack_data_file)

        return attack_data_file.custom_index or self.sync_obj.replay_index

    def hec_raw_replay(
        self,
        tempfile: str,
        attack_data_file: UnitTestAttackData,
        verify_ssl: bool = False,
    ):
        if verify_ssl is False:
            # need this, otherwise every request made with the requests module
            # and verify=False will print an error to the command line
            disable_warnings()

        # build the headers

        headers = {
            "Authorization": f"Splunk {self.hec_token}",  # token must begin with 'Splunk '
            "X-Splunk-Request-Channel": self.hec_channel,
        }

        url_params = {
            "index": attack_data_file.custom_index or self.sync_obj.replay_index,
            "source": attack_data_file.source,
            "sourcetype": attack_data_file.sourcetype,
            "host": attack_data_file.host or self.sync_obj.replay_host,
        }

        if self.infrastructure.instance_address.strip().lower().startswith("https://"):
            address_with_scheme = self.infrastructure.instance_address.strip().lower()
        elif self.infrastructure.instance_address.strip().lower().startswith("http://"):
            address_with_scheme = (
                self.infrastructure.instance_address.strip()
                .lower()
                .replace("http://", "https://")
            )
        else:
            address_with_scheme = f"https://{self.infrastructure.instance_address}"

        # Generate the full URL, including the host, the path, and the params.
        # We can be a lot smarter about this (and pulling the port from the url, checking
        # for trailing /, etc, but we leave that for the future)
        url_with_port = f"{address_with_scheme}:{self.infrastructure.hec_port}"
        url_with_hec_path = urllib.parse.urljoin(
            url_with_port, "services/collector/raw"
        )
        with open(tempfile, "rb") as datafile:
            try:
                res = requests.post(
                    url_with_hec_path,
                    params=url_params,
                    data=datafile.read(),
                    allow_redirects=True,
                    headers=headers,
                    verify=verify_ssl,
                )
                jsonResponse = json.loads(res.text)

            except Exception as e:
                raise (
                    Exception(
                        f"There was an exception sending attack_data to HEC: {str(e)}"
                    )
                )

        if "ackId" not in jsonResponse:
            raise (
                Exception(
                    f"key 'ackID' not present in response from HEC server: {jsonResponse}"
                )
            )

        ackId = jsonResponse["ackId"]
        url_with_hec_ack_path = urllib.parse.urljoin(
            url_with_port, "services/collector/ack"
        )

        requested_acks = {"acks": [jsonResponse["ackId"]]}
        while True:
            try:

                res = requests.post(
                    url_with_hec_ack_path,
                    json=requested_acks,
                    allow_redirects=True,
                    headers=headers,
                    verify=verify_ssl,
                )

                jsonResponse = json.loads(res.text)

                if "acks" in jsonResponse and str(ackId) in jsonResponse["acks"]:
                    if jsonResponse["acks"][str(ackId)] is True:
                        # ackID has been found for our request, we can return as the data has been replayed
                        return
                    else:
                        # ackID is not yet true, we will wait some more
                        time.sleep(2)

                else:
                    raise (
                        Exception(
                            f"Proper ackID structure not found for ackID {ackId} in {jsonResponse}"
                        )
                    )
            except Exception as e:
                raise (Exception(f"There was an exception in the post: {str(e)}"))

    def status(self):
        pass

    def finish(self):
        self.pbar.bar_format = f"Stopped container [{self.get_name()}]"
        self.pbar.update()
        self.pbar.close()

    def check_health(self):
        pass
