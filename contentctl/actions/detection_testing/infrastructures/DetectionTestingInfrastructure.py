import logging
import time
import uuid
import abc
import os.path
import configparser
import json
import datetime
import tqdm                                                                                         # type: ignore
import pathlib
from tempfile import TemporaryDirectory, mktemp
from ssl import SSLEOFError, SSLZeroReturnError
from sys import stdout
from shutil import copyfile
from typing import Union, Optional

from pydantic import ConfigDict, BaseModel, PrivateAttr, Field, dataclasses
import requests                                                                                     # type: ignore
import splunklib.client as client                                                                   # type: ignore
from splunklib.binding import HTTPError                                                             # type: ignore
from splunklib.client import Service
from splunklib.results import JSONResultsReader, Message                                            # type: ignore
import splunklib.results
from urllib3 import disable_warnings
import urllib.parse

from contentctl.objects.config import test_common, Infrastructure, ENTERPRISE_SECURITY_UID
from contentctl.objects.enums import PostTestBehavior, AnalyticsType
from contentctl.objects.detection import Detection
from contentctl.objects.base_test import BaseTest
from contentctl.objects.unit_test import UnitTest
from contentctl.objects.integration_test import IntegrationTest
from contentctl.objects.test_attack_data import TestAttackData
from contentctl.objects.unit_test_result import UnitTestResult
from contentctl.objects.integration_test_result import IntegrationTestResult
from contentctl.objects.test_group import TestGroup
from contentctl.objects.base_test_result import TestResultStatus
from contentctl.objects.correlation_search import CorrelationSearch, PbarData
from contentctl.helper.utils import Utils
from contentctl.actions.detection_testing.progress_bar import (
    format_pbar_string,
    TestReportingType,
    FinalTestingStates,
    TestingStates
)

LOG = Utils.get_logger()


class SetupTestGroupResults(BaseModel):
    exception: Union[Exception, None] = None
    success: bool = True
    duration: float = 0
    start_time: float
    model_config = ConfigDict(
        arbitrary_types_allowed=True
    )


class CleanupTestGroupResults(BaseModel):
    duration: float
    start_time: float


class ContainerStoppedException(Exception):
    pass
class CannotRunBaselineException(Exception):
    # Support for testing detections with baselines 
    # does not currently exist in contentctl.
    # As such, whenever we encounter a detection 
    # with baselines we should generate a descriptive
    # exception
    pass

class ReplayIndexDoesNotExistOnServer(Exception):
    '''
    In order to replay data files into the Splunk Server
    for testing, they must be replayed into an index that
    exists. If that index does not exist, this error will
    be generated and raised before we try to do anything else
    with that Data File.
    '''
    pass

@dataclasses.dataclass(frozen=False)
class DetectionTestingManagerOutputDto():
    inputQueue: list[Detection] = Field(default_factory=list)
    outputQueue: list[Detection] = Field(default_factory=list)
    currentTestingQueue: dict[str, Union[Detection, None]] = Field(default_factory=dict)
    start_time: Union[datetime.datetime, None] = None
    replay_index: str = "contentctl_testing_index"
    replay_host: str = "CONTENTCTL_HOST"
    timeout_seconds: int = 60
    terminate: bool = False


class DetectionTestingInfrastructure(BaseModel, abc.ABC):
    # thread: threading.Thread = threading.Thread()
    global_config: test_common
    infrastructure: Infrastructure
    sync_obj: DetectionTestingManagerOutputDto
    hec_token: str = ""
    hec_channel: str = ""
    all_indexes_on_server: list[str] = []
    _conn: client.Service = PrivateAttr()
    pbar: tqdm.tqdm = None
    start_time: Optional[float] = None
    model_config = ConfigDict(
        arbitrary_types_allowed=True
    )

    def __init__(self, **data):
        super().__init__(**data)
        self._conn: None | Service = None

    # TODO: why not use @abstractmethod
    def start(self):
        raise (
            NotImplementedError(
                "start() is not implemented for Abstract Type DetectionTestingInfrastructure"
            )
        )

    # TODO: why not use @abstractmethod
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
                (self.get_conn, "Getting initial connection"),
                (self.wait_for_app_installation, "Waiting for App Installation"),
                (self.configure_conf_file_datamodels, "Configuring Datamodels"),
                (self.create_replay_index, f"Create index '{self.sync_obj.replay_index}'"),
                (self.get_all_indexes, "Getting all indexes from server"),
                (self.configure_imported_roles, "Configuring Roles"),
                (self.configure_delete_indexes, "Configuring Indexes"),
                (self.configure_hec, "Configuring HEC"),
                (self.wait_for_ui_ready, "Finishing Setup")
            ]:

                self.format_pbar_string(
                    TestReportingType.SETUP,
                    self.get_name(),
                    msg,
                    update_sync_status=True,
                )
                func()
                self.check_for_teardown()

        except Exception as e:
            self.pbar.write(str(e))
            self.finish()
            return

        self.format_pbar_string(TestReportingType.SETUP, self.get_name(), "Finished Setup!")

    def wait_for_ui_ready(self):
        self.get_conn()

    def configure_hec(self):
        self.hec_channel = str(uuid.uuid4())
        try:
            # Delete old HEC
            self.get_conn().inputs.delete("DETECTION_TESTING_HEC", kind='http')
        except (HTTPError, KeyError) as e:
            # HEC input didn't exist in the first place, everything is good.
            pass
        except Exception as e:
            LOG.error("Error when deleting input DETECTION_TESTING_HEC.")
            LOG.exception(e)
            raise e

        try:
            res = self.get_conn().inputs.create(
                name="DETECTION_TESTING_HEC",
                kind="http",
                index=self.sync_obj.replay_index,
                indexes=",".join(self.all_indexes_on_server), # This allows the HEC to write to all indexes
                useACK=True,
            )
            self.hec_token = str(res.token)
            return

        except Exception as e:
            raise (Exception(f"Failure creating HEC Endpoint: {str(e)}"))

    def get_all_indexes(self) -> None:
        """
        Retrieve a list of all indexes in the Splunk instance
        """
        try:
            # We do not include the replay index because by
            # the time we get to this function, it has already
            # been created on the server.
            indexes = []
            res = self.get_conn().indexes
            for index in res.list():
                indexes.append(index.name)
            # Retrieve all available indexes on the splunk instance
            self.all_indexes_on_server = indexes
        except Exception as e:
            raise (Exception(f"Failure getting indexes: {str(e)}"))

    def wait_for_app_installation(self):
        config_apps = self.global_config.apps
        installed_config_apps = []
        while len(installed_config_apps) < len(config_apps):
            try:
                # Get apps installed in the Splunk instance
                splunk_instance_apps = self.get_conn().apps.list()

                # Try to find all the apps we want to be installed (config_apps)
                installed_config_apps = []
                for config_app in config_apps:
                    for splunk_instance_app in splunk_instance_apps:
                        if config_app.appid == splunk_instance_app.name:
                            # For Enterprise Security, we need to make sure the app is also configured.
                            if config_app.uid == ENTERPRISE_SECURITY_UID and splunk_instance_app.content.get('configured') != '1':
                                continue
                            installed_config_apps.append(config_app.appid)
                LOG.debug("Apps in the Splunk instance: " + str(list(map(lambda x: x.name, splunk_instance_apps))))
                LOG.debug(f"apps in contentctl package found in Splunk instance: {installed_config_apps}")
                if len(installed_config_apps) >= len(config_apps):
                    break
            except Exception as e:
                LOG.exception(e)
            time.sleep(5)

    def get_conn(self) -> client.Service:
        try:
            if not self._conn:
                self.connect_to_api()
            elif self._conn.restart_required:
                # continue trying to re-establish a connection until after
                # the server has restarted
                self.connect_to_api()
        except Exception as e:
            # there was some issue getting the connection. Try again just once
            LOG.exception(e)
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

            for _ in range(sleep_seconds):
                self.format_pbar_string(
                    TestReportingType.SETUP,
                    self.get_name(),
                    "Getting API Connection",
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
    ):  
        try:
            # Set which roles should be configured. For Enterprise Security/Integration Testing,
            # we must add some extra roles.
            if self.global_config.enable_integration_testing:
                roles = imported_roles + enterprise_security_roles
            else:
                roles = imported_roles

            self.get_conn().roles.post(
                self.infrastructure.splunk_app_username,
                imported_roles=roles,
                srchIndexesAllowed=";".join(self.all_indexes_on_server),
                srchIndexesDefault=self.sync_obj.replay_index,
            )
            return
        except Exception as e:
            self.pbar.write(
                f"The following role(s) do not exist:'{enterprise_security_roles}: {str(e)}"
            )

        self.get_conn().roles.post(
            self.infrastructure.splunk_app_username,
            imported_roles=imported_roles,
            srchIndexesAllowed=";".join(self.all_indexes_on_server),
            srchIndexesDefault=self.sync_obj.replay_index,
        )

    def configure_delete_indexes(self):
        endpoint = "/services/properties/authorize/default/deleteIndexesAllowed"
        try:
            self.get_conn().post(endpoint, value=";".join(self.all_indexes_on_server))
        except Exception as e:
            self.pbar.write(
                f"Error configuring deleteIndexesAllowed with '{self.all_indexes_on_server}': [{str(e)}]"
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
                self.pbar.write(f"Warning - container was stopped when trying to execute detection [{self.get_name()}]")
                self.finish()
                return
            except Exception as e:
                self.pbar.write(f"Error testing detection: {type(e).__name__}: {str(e)}")
                raise e
            finally:
                self.sync_obj.outputQueue.append(detection)
                self.sync_obj.currentTestingQueue[self.get_name()] = None

    def test_detection(self, detection: Detection) -> None:
        """
        Tests a single detection; iterates over the TestGroups for the detection (one TestGroup per
        unit test, where a TestGroup is a unit test and integration test relying on the same attack
        data)
        :param detection: the Detection to test
        """

        # iterate TestGroups
        for test_group in detection.test_groups:
            # If all tests in the group have been skipped, report and continue.
            # Note that the logic for skipping tests for detections tagged manual_test exists in
            # the detection builder.
            if test_group.all_tests_skipped():
                self.pbar.write(
                    self.format_pbar_string(
                        TestReportingType.GROUP,
                        test_group.name,
                        FinalTestingStates.SKIP.value,
                        start_time=time.time(),
                        set_pbar=False,
                    )
                )
                continue

            # replay attack_data
            setup_results = self.setup_test_group(test_group)

            # run unit test
            self.execute_unit_test(detection, test_group.unit_test, setup_results)

            # run integration test
            self.execute_integration_test(
                detection,
                test_group.integration_test,
                setup_results,
                test_group.unit_test.result
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

            # Write test group status
            self.pbar.write(
                self.format_pbar_string(
                    TestReportingType.GROUP,
                    test_group.name,
                    TestingStates.DONE_GROUP.value,
                    start_time=setup_results.start_time,
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

        # Log the start of the test group
        self.pbar.reset()
        self.format_pbar_string(
            TestReportingType.GROUP,
            test_group.name,
            TestingStates.BEGINNING_GROUP.value,
            start_time=setup_start_time
        )
        # https://github.com/WoLpH/python-progressbar/issues/164
        # Use NullBar if there is more than 1 container or we are running
        # in a non-interactive context

        # Initialize the setup results
        results = SetupTestGroupResults(start_time=setup_start_time)

        # Replay attack data
        try:
            self.replay_attack_data_files(test_group, setup_start_time)
        except Exception as e:
            print("\n\nexception replaying attack data files\n\n")
            results.exception = e
            results.success = False

        # Set setup duration
        results.duration = time.time() - setup_start_time

        return results

    def cleanup_test_group(
        self,
        test_group: TestGroup,
        test_group_start_time: float,
    ) -> CleanupTestGroupResults:
        """
        Deletes attack data for the test group and returns metadata about the cleanup duration
        :param test_group: the TestGroup being cleaned up
        :param test_group_start_time: the start time of the TestGroup (for logging)
        """
        # Get the start time for cleanup
        cleanup_start_time = time.time()

        # Log the cleanup action
        self.format_pbar_string(
            TestReportingType.GROUP,
            test_group.name,
            TestingStates.DELETING.value,
            start_time=test_group_start_time,
        )

        # TODO: do we want to clean up even if replay failed? Could have been partial failure?
        # Delete attack data
        self.delete_attack_data(test_group.attack_data)

        # Return the cleanup metadata, adding start time and duration
        return CleanupTestGroupResults(
            duration=time.time() - cleanup_start_time,
            start_time=cleanup_start_time
        )

    def format_pbar_string(
        self,
        test_reporting_type: TestReportingType,
        test_name: str,
        state: str,
        start_time: Optional[float] = None,
        set_pbar: bool = True,
        update_sync_status: bool = False,
    ) -> str:
        """
        Instance specific function to log testing information via pbar; returns a formatted string
        that can be written and optionally updates the existing progress bar
        :param test_reporting_type: the type of reporting to be done (e.g. unit, integration, group)
        :param test_name: the name of the test to be logged
        :param state: the state/message of the test to be logged
        :param start_time: the start_time of this progres bar
        :param set_pbar: bool indicating whether pbar.update should be called
        :param update_sync_status: bool indicating whether a sync status update should be queued
        :returns: a formatted string for use w/ pbar
        """
        # set start time if not provided
        if start_time is None:
            # if self.start_time is still None, something went wrong
            if self.start_time is None:
                raise ValueError(
                    "self.start_time is still None; a function may have been called before self.setup()"
                )
            start_time = self.start_time

        # invoke the helper method
        new_string = format_pbar_string(
            self.pbar,
            test_reporting_type,
            test_name,
            state,
            start_time,
            set_pbar
        )

        # update sync status if needed
        if update_sync_status:
            self.sync_obj.currentTestingQueue[self.get_name()] = {                                  # type: ignore
                "name": state,
                "search": "N/A",
            }

        # return the formatted string
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
            start_time=test_start_time,
        )

        # if the replay failed, record the test failure and return
        if not setup_results.success:
            test.result = UnitTestResult()
            test.result.set_job_content(
                None,
                self.infrastructure,
                TestResultStatus.ERROR,
                exception=setup_results.exception,
                duration=time.time() - test_start_time
            )

            # report the failure to the CLI
            self.pbar.write(
                self.format_pbar_string(
                    TestReportingType.UNIT,
                    f"{detection.name}:{test.name}",
                    FinalTestingStates.ERROR.value,
                    start_time=test_start_time,
                    set_pbar=False,
                )
            )

            return

        # Set the mode and timeframe, if required
        kwargs = {"exec_mode": "blocking"}

        # Set earliest_time and latest_time appropriately if FORCE_ALL_TIME is False
        if not FORCE_ALL_TIME:
            if test.earliest_time is not None:
                kwargs.update({"earliest_time": test.earliest_time})
            if test.latest_time is not None:
                kwargs.update({"latest_time": test.latest_time})

        # Run the detection's search query
        try:
            # Iterate over baselines (if any)
            for baseline in detection.baselines:
                raise CannotRunBaselineException("Detection requires Execution of a Baseline, "
                                                 "however Baseline execution is not "
                                                 "currently supported in contentctl. Mark "
                                                 "this as manual_test.")
            self.retry_search_until_timeout(detection, test, kwargs, test_start_time)
        except CannotRunBaselineException as e:
            # Init the test result and record a failure if there was an issue during the search
            test.result = UnitTestResult()
            test.result.set_job_content(
                None,
                self.infrastructure,
                TestResultStatus.ERROR,
                exception=e,
                duration=time.time() - test_start_time
            )
        except ContainerStoppedException as e:
            raise e
        except Exception as e:
            # Init the test result and record a failure if there was an issue during the search
            print("\n\nexception trying search until timeout\n\n")
            test.result = UnitTestResult()
            test.result.set_job_content(
                None,
                self.infrastructure,
                TestResultStatus.ERROR,
                exception=e,
                duration=time.time() - test_start_time
            )

        # Pause here if the terminate flag has NOT been set AND either of the below are true:
        #   1. the behavior is always_pause
        #   2. the behavior is pause_on_failure and the test failed
        if self.pause_for_user(test):
            # Determine the state to report to the user
            if test.result is None:
                res = "ERROR"
                link = detection.search
            else:
                res = test.result.status.value.upper()                                              # type: ignore
                link = test.result.get_summary_dict()["sid_link"]

            self.format_pbar_string(
                TestReportingType.UNIT,
                f"{detection.name}:{test.name}",
                f"{res} - {link} (CTRL+D to continue)",
                start_time=test_start_time,
            )

            # Wait for user input
            try:
                _ = input()
            except Exception:
                pass

        # Treat the case where no result is created as an error
        if test.result is None:
            message = "TEST ERROR: No result generated during testing"
            test.result = UnitTestResult(
                message=message,
                exception=ValueError(message),
                status=TestResultStatus.ERROR
            )

        # Report a pass
        if test.result.status == TestResultStatus.PASS:
            self.pbar.write(
                self.format_pbar_string(
                    TestReportingType.UNIT,
                    f"{detection.name}:{test.name}",
                    FinalTestingStates.PASS.value,
                    start_time=test_start_time,
                    set_pbar=False,
                )
            )
        elif test.result.status == TestResultStatus.SKIP:
            # Report a skip
            self.pbar.write(
                self.format_pbar_string(
                    TestReportingType.UNIT,
                    f"{detection.name}:{test.name}",
                    FinalTestingStates.SKIP.value,
                    start_time=test_start_time,
                    set_pbar=False,
                )
            )
        elif test.result.status == TestResultStatus.FAIL:
            # Report a FAIL
            self.pbar.write(
                self.format_pbar_string(
                    TestReportingType.UNIT,
                    f"{detection.name}:{test.name}",
                    FinalTestingStates.FAIL.value,
                    start_time=test_start_time,
                    set_pbar=False,
                )
            )
        elif test.result.status == TestResultStatus.ERROR:
            # Report an ERROR
            self.pbar.write(
                self.format_pbar_string(
                    TestReportingType.UNIT,
                    f"{detection.name}:{test.name}",
                    FinalTestingStates.ERROR.value,
                    start_time=test_start_time,
                    set_pbar=False,
                )
            )
        else:
            # Status was None or some other unexpected value
            raise ValueError(
                f"Status for (unit) '{detection.name}:{test.name}' was an unexpected"
                f"value: {test.result.status}"
            )

        # Flush stdout and set duration
        stdout.flush()
        test.result.duration = round(time.time() - test_start_time, 2)

    # TODO (#227): break up the execute routines for integration/unit tests some more to remove
    #   code w/ similar structure
    def execute_integration_test(
        self,
        detection: Detection,
        test: IntegrationTest,
        setup_results: SetupTestGroupResults,
        unit_test_result: Optional[UnitTestResult]
    ):
        """
        Executes an integration test on the detection
        :param detection: the detection on which to run the test
        """
        # Capture unit test start time
        test_start_time = time.time()

        # First, check to see if the test should be skipped (Hunting or Correlation)
        if detection.type in [AnalyticsType.Hunting.value, AnalyticsType.Correlation.value]:
            test.skip(
                f"TEST SKIPPED: detection is type {detection.type} and cannot be integration "
                "tested at this time"
            )

        # Next, check to see if the unit test failed; preemptively fail integration testing if so
        if unit_test_result is not None:
            # check status is set (complete) and if failed (FAIL/ERROR)
            if unit_test_result.complete and unit_test_result.failed:
                test.result = IntegrationTestResult(
                    message="TEST FAILED (PREEMPTIVE): associated unit test failed or encountered an error",
                    exception=unit_test_result.exception,
                    status=unit_test_result.status,
                )

        # Next, check to see if this test has already had its status set (just now or elsewhere);
        # log and return if so
        if (test.result is not None) and test.result.complete:
            # Determine the reporting state (we should only encounter SKIP/FAIL/ERROR)
            state: str
            if test.result.status == TestResultStatus.SKIP:
                state = FinalTestingStates.SKIP.value
            elif test.result.status == TestResultStatus.FAIL:
                state = FinalTestingStates.FAIL.value
            elif test.result.status == TestResultStatus.ERROR:
                state = FinalTestingStates.ERROR.value
            else:
                raise ValueError(
                    f"Status for (integration) '{detection.name}:{test.name}' was preemptively set"
                    f"to an unexpected value: {test.result.status}"
                )
            # report the status to the CLI
            self.pbar.write(
                self.format_pbar_string(
                    TestReportingType.INTEGRATION,
                    f"{detection.name}:{test.name}",
                    state,
                    start_time=test_start_time,
                    set_pbar=False,
                )
            )
            return

        # Reset the pbar and print that we are beginning an integration test
        self.pbar.reset()
        self.format_pbar_string(
            TestReportingType.INTEGRATION,
            f"{detection.name}:{test.name}",
            TestingStates.BEGINNING_TEST,
            start_time=test_start_time,
        )

        # if the replay failed, record the test failure and return
        if not setup_results.success:
            test.result = IntegrationTestResult(
                message=(
                    "TEST FAILED (ERROR): something went wrong during during TestGroup setup (e.g. "
                    "attack data replay)"
                ),
                exception=setup_results.exception,
                duration=round(time.time() - test_start_time, 2),
                status=TestResultStatus.ERROR
            )

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

            return

        # Run the test
        try:
            # Capture pbar data for CorrelationSearch logging
            pbar_data = PbarData(
                pbar=self.pbar,
                fq_test_name=f"{detection.name}:{test.name}",
                start_time=test_start_time
            )

            # TODO (#228): consider reusing CorrelationSearch instances across test cases
            # Instantiate the CorrelationSearch
            correlation_search = CorrelationSearch(
                detection=detection,
                service=self.get_conn(),
                pbar_data=pbar_data,
            )

            # Run the test
            test.result = correlation_search.test()
        except Exception as e:
            # Catch and report and unhandled exceptions in integration testing
            test.result = IntegrationTestResult(
                message="TEST ERROR: unhandled exception in CorrelationSearch",
                exception=e,
                status=TestResultStatus.ERROR
            )

        # TODO (#229): when in interactive mode, cleanup should happen after user interaction
        # Pause here if the terminate flag has NOT been set AND either of the below are true:
        #   1. the behavior is always_pause
        #   2. the behavior is pause_on_failure and the test failed
        if self.pause_for_user(test):
            # Determine the state to report to the user
            if test.result is None:
                res = "ERROR"
            else:
                res = test.result.status.value.upper()                                              # type: ignore

            # Get the link to the saved search in this specific instance
            link = f"https://{self.infrastructure.instance_address}:{self.infrastructure.web_ui_port}"

            self.format_pbar_string(
                TestReportingType.INTEGRATION,
                f"{detection.name}:{test.name}",
                f"{res} - {link} (CTRL+D to continue)",
                start_time=test_start_time,
            )

            # Wait for user input
            try:
                _ = input()
            except Exception:
                pass

        # Treat the case where no result is created as an error
        if test.result is None:
            message = "TEST ERROR: No result generated during testing"
            test.result = IntegrationTestResult(
                message=message,
                exception=ValueError(message),
                status=TestResultStatus.ERROR
            )

        # Report a pass
        if test.result.status == TestResultStatus.PASS:
            self.pbar.write(
                self.format_pbar_string(
                    TestReportingType.INTEGRATION,
                    f"{detection.name}:{test.name}",
                    FinalTestingStates.PASS.value,
                    start_time=test_start_time,
                    set_pbar=False,
                )
            )
        elif test.result.status == TestResultStatus.SKIP:
            # Report a skip
            self.pbar.write(
                self.format_pbar_string(
                    TestReportingType.INTEGRATION,
                    f"{detection.name}:{test.name}",
                    FinalTestingStates.SKIP.value,
                    start_time=test_start_time,
                    set_pbar=False,
                )
            )
        elif test.result.status == TestResultStatus.FAIL:
            # report a FAIL
            self.pbar.write(
                self.format_pbar_string(
                    TestReportingType.INTEGRATION,
                    f"{detection.name}:{test.name}",
                    FinalTestingStates.FAIL.value,
                    start_time=test_start_time,
                    set_pbar=False,
                )
            )
        elif test.result.status == TestResultStatus.ERROR:
            # report an ERROR
            self.pbar.write(
                self.format_pbar_string(
                    TestReportingType.INTEGRATION,
                    f"{detection.name}:{test.name}",
                    FinalTestingStates.ERROR.value,
                    start_time=test_start_time,
                    set_pbar=False,
                )
            )
        else:
            # Status was None or some other unexpected value
            raise ValueError(
                f"Status for (integration) '{detection.name}:{test.name}' was an "
                f"unexpected value: {test.result.status}"
            )

        # Flush stdout and set duration
        stdout.flush()
        test.result.duration = round(time.time() - test_start_time, 2)

    def pause_for_user(self, test: BaseTest) -> bool:
        """
        Returns true if test execution should pause for user investigation
        :param test: the test instance
        :returns: bool where True indicates we should pause for the user
        """
        # Ensure the worker has not been terminated
        if not self.sync_obj.terminate:
            # check if the behavior is to always pause
            if self.global_config.post_test_behavior == PostTestBehavior.always_pause:
                return True
            elif self.global_config.post_test_behavior == PostTestBehavior.pause_on_failure:
                # If the behavior is to pause on failure, check for failure (either explicitly, or
                # just a lack of a result)
                if test.result is None or test.result.failed:
                    return True

        # Otherwise, don't pause
        return False

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

        # Make a copy of the search string since we may
        # need to make some small changes to it below
        search = detection.search

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
                    start_time=start_time
                )

                time.sleep(1)

            self.format_pbar_string(
                TestReportingType.UNIT,
                f"{detection.name}:{test.name}",
                TestingStates.SEARCHING.value,
                start_time=start_time,
            )

            # Execute the search and read the results
            job = self.get_conn().search(query=search, **kwargs)
            results = JSONResultsReader(job.results(output_mode="json"))

            # Consolidate a set of the distinct observable field names
            observable_fields_set = set([o.name for o in detection.tags.observable]) # keeping this around for later
            risk_object_fields_set = set([o.name for o in detection.tags.observable if "Victim" in o.role ]) # just the "Risk Objects"
            threat_object_fields_set = set([o.name for o in detection.tags.observable if "Attacker" in o.role]) # just the "threat objects"

            # Ensure the search had at least one result
            if int(job.content["resultCount"]) > 0:
                # Initialize the test result
                test.result = UnitTestResult()

                # Initialize the collection of fields that are empty that shouldn't be
                present_threat_objects: set[str] = set()
                empty_fields: set[str] = set()

                # Filter out any messages in the results
                for result in results:
                    if isinstance(result, Message):
                        continue

                    # If not a message, it is a dict and we will process it
                    results_fields_set = set(result.keys())
                    # Guard against first events (relevant later)

                    # Identify any risk object fields that are not available in the results
                    missing_risk_objects = risk_object_fields_set - results_fields_set
                    if len(missing_risk_objects) > 0:
                        # Report a failure in such cases
                        e = Exception(f"The observable field(s) {missing_risk_objects} are missing in the detection results")
                        test.result.set_job_content(
                            job.content,
                            self.infrastructure,
                            TestResultStatus.FAIL,
                            exception=e,
                            duration=time.time() - search_start_time,
                        )

                        return                    

                    # If we find one or more risk object fields that contain the string "null" then they were
                    # not populated and we should throw an error.  This can happen if there is a typo
                    # on a field.  In this case, the field will appear but will not contain any values
                    current_empty_fields: set[str] = set()

                    for field in observable_fields_set:
                        if result.get(field, 'null') == 'null':
                            if field in risk_object_fields_set:
                                e = Exception(f"The risk object field {field} is missing in at least one result.")
                                test.result.set_job_content(
                                    job.content,
                                    self.infrastructure,
                                    TestResultStatus.FAIL,
                                    exception=e,
                                    duration=time.time() - search_start_time,
                                )
                                return
                            else:
                                if field in threat_object_fields_set:
                                    current_empty_fields.add(field)
                        else:
                            if field in threat_object_fields_set:
                                present_threat_objects.add(field)
                                continue

                    # If everything succeeded up until now, and no empty fields are found in the
                    # current result, then the search was a success
                    if len(current_empty_fields) == 0:
                        test.result.set_job_content(
                            job.content,
                            self.infrastructure,
                            TestResultStatus.PASS,
                            duration=time.time() - search_start_time,
                        )
                        return

                    else:
                        empty_fields = empty_fields.union(current_empty_fields)

                missing_threat_objects = threat_object_fields_set - present_threat_objects
                # Report a failure if there were empty fields in a threat object in all results
                if len(missing_threat_objects) > 0:
                    e = Exception(
                        f"One or more required threat object fields {missing_threat_objects} contained 'null' values in all events. "
                        "Is the data being parsed correctly or is there an error in the naming of a field?"
                    )
                    test.result.set_job_content(
                        job.content,
                        self.infrastructure,
                        TestResultStatus.FAIL,
                        exception=e,
                        duration=time.time() - search_start_time,
                    )
                    return

                test.result.set_job_content(
                            job.content,
                            self.infrastructure,
                            TestResultStatus.PASS,
                            duration=time.time() - search_start_time,
                        )
                return               

            else:
                # Report a failure if there were no results at all
                test.result = UnitTestResult()
                test.result.set_job_content(
                    job.content,
                    self.infrastructure,
                    TestResultStatus.FAIL,
                    duration=time.time() - search_start_time,
                    message=f"Search had 0 result. {job.content}"
                )
                tick += 1

        return

    def delete_attack_data(self, attack_data_files: list[TestAttackData]):
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
        attack_data_file: TestAttackData,
        tmp_dir: str,
        test_group: TestGroup,
        test_group_start_time: float,
    ):
        # Before attempting to replay the file, ensure that the index we want
        # to replay into actually exists. If not, we create the index.
        if attack_data_file.custom_index is not None and \
            attack_data_file.custom_index not in self.all_indexes_on_server:
            index = self.get_conn().indexes.create(name=attack_data_file.custom_index)
            LOG.info(f"Created Index {attack_data_file.custom_index}: {index}")
            LOG.info("Re-retup of the HEC and roles and indexes...")
            self.get_all_indexes()
            self.configure_imported_roles()
            self.configure_delete_indexes()
            self.configure_hec()

        tempfile = mktemp(dir=tmp_dir)
        if not (str(attack_data_file.data).startswith("http://") or 
                str(attack_data_file.data).startswith("https://")) :
            if pathlib.Path(str(attack_data_file.data)).is_file():
                self.format_pbar_string(TestReportingType.GROUP, 
                                        test_group.name, 
                                        "Copying Data", 
                                        test_group_start_time)

                try:
                    copyfile(str(attack_data_file.data), tempfile)
                except Exception as e:
                    raise Exception(
                        f"Error copying local Attack Data File for [{test_group.name}] - [{attack_data_file.data}]: "
                        f"{str(e)}"
                    )
            else:
                raise Exception(
                    f"Attack Data File for [{test_group.name}] is local [{attack_data_file.data}], but does not exist."
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
                    start_time=test_group_start_time
                )

                Utils.download_file_from_http(
                    str(attack_data_file.data), tempfile, self.pbar, overwrite_file=True
                )
            except Exception as e:
                raise (
                    Exception(
                        f"Could not download attack data file [{attack_data_file.data}]:{str(e)}"
                    )
                )

        # Upload the data
        self.format_pbar_string(
            TestReportingType.GROUP,
            test_group.name,
            TestingStates.REPLAYING.value,
            start_time=test_group_start_time
        )

        self.hec_raw_replay(tempfile, attack_data_file)

        return attack_data_file.custom_index or self.sync_obj.replay_index

    def hec_raw_replay(
        self,
        tempfile: str,
        attack_data_file: TestAttackData,
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
        with open(tempfile, "r") as datafile:
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
        self.pbar.bar_format = f"Finished running tests on instance: [{self.get_name()}]"
        self.pbar.update()
        self.pbar.close()

    def check_health(self):
        pass
