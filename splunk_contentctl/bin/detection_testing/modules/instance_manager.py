from collections import OrderedDict
from tabnanny import check
import docker
import datetime
import docker.types
import os
import random

import json
import string
import threading
import time
import timeit
import queue
from typing import Union
from bin.detection_testing.modules.splunk_instance import SplunkInstance, SplunkContainer, SplunkServer
from bin.detection_testing.modules.shared_test_objects import SharedTestObjects
from bin.objects.enums import DetectionTestingTargetInfrastructure
from bin.objects.detection import Detection
from bin.objects.test_config import TestConfig


from tempfile import mkdtemp
import pathlib
import shutil
import psutil

WEB_PORT_START = 8000
HEC_PORT_START = 8088
MANAGEMENT_PORT_START = 8089


class InstanceManager:
    def __init__(self,
                 config: TestConfig,
                 detections: list[Detection],
                 files_to_copy_to_container: OrderedDict = OrderedDict()):

        self.config = config
        self.files_to_copy_to_container = files_to_copy_to_container

        self.shared_test_objects = SharedTestObjects(
            detections, self.config.num_containers)

        print("\n\n***********************")
        print(f"Log into your [{self.config.num_containers}] Splunk Instance(s) after they are ready at http://127.0.0.1:[{WEB_PORT_START}-{WEB_PORT_START + self.config.num_containers - 1}]")
        print("\tSplunk App Username: [%s]" % ("admin"))
        print("\tSplunk App Password: ", end='')

        print("[%s]" % (self.config.splunk_app_password))

        print("***********************\n\n")

        if self.config.target_infrastructure == DetectionTestingTargetInfrastructure.container:
            print("start and set up some containers")
        else:
            print("it's just a server that is already set up")

        self.summary_thread = threading.Thread(
            target=self.queue_status_thread, args=())

        print("CODE TO GENERATE YOUR BASELINE INFORMATION HERE")

        # Construct the baseline from the splunk version and the apps to be installed
        self.baseline = self.generate_baseline()

        self.instances: list[splunk_instance.SplunkInstance] = []

    def generate_baseline(self) -> OrderedDict:
        baseline = OrderedDict()
        '''
        #Get a datetime and add it as the first entry in the baseline
        self.start_time = datetime.datetime.now()
        self.baseline['SPLUNK_VERSION'] = full_docker_hub_name
        self.baseline["branch"] = branch
        self.baseline["commit_hash"] = commit_hash
        #Added here first to preserve ordering for OrderedDict
        self.baseline['TEST_START_TIME'] = "TO BE UPDATED"
        self.baseline['TEST_FINISH_TIME'] = "TO BE UPDATED"
        self.baseline['TEST_DURATION'] = "TO BE UPDATED"

        for key in self.config.apps:
            self.baseline[key] = self.apps[key]

        '''
        return baseline

    def run_test(self) -> bool:
        self.run_status_thread()
        self.run_instances()
        self.summary_thread.join()

        print("sleep to prevent the cleanup...")
        time.sleep(1600)

        for instance in self.instances:
            if self.all_tests_completed == True:
                instance.thread.join()
            elif self.all_tests_completed == False:
                # For some reason, we stopped early.  So don't wait on the child threads to finish. Don't join,
                # these threads may be stuck in their setup loops. Continue on.
                pass

            print("Output the summary at the end")
            # print(instance.get_container_summary())

        print("All containers completed testing!")

        return self.finish()

    def finish(self):
        self.cleanup()
        if self.shared_test_objects.pass_count == self.shared_test_objects.total_number_of_detections:
            return True
        # There was at least one failure or skipped test, so we did not succeed
        return False

    def cleanup(self):

        try:
            print(
                "Removing all attack data that was downloaded during this test at: [{self.shared_test_objects.attack_data_root_folder}]")
            shutil.rmtree(self.shared_test_objects.attack_data_root_folder)
            print("Successfully removed all attack data")
        finally:
            pass

    def get_system_stats(self) -> str:
        # System stats are only useful in some cases (when Splunk is running locally)
        bytes_per_GB = 1024 * 1024 * 1024
        cpu_info = psutil.cpu_times_percent(percpu=False)
        memory_info = psutil.virtual_memory()
        disk_usage_info = psutil.disk_usage('/')

        # macOS is really weird about disk usage.... so to get free space we use TOTAL-FREE = USED instead of just USED
        corrected_used_space = disk_usage_info.total - disk_usage_info.free

        cpu_info_string = "Total CPU Usage   : %d%% (%d CPUs)" % (
            100 - cpu_info.idle, psutil.cpu_count(logical=False))
        memory_info_string = "Total Memory Usage: %0.1fGB USED / %0.1fGB TOTAL" % (
            (memory_info.total - memory_info.available) / bytes_per_GB, memory_info.total / bytes_per_GB)
        disk_usage_info_string = "Total Disk Usage  : %0.1fGB USED / %0.1fGB TOTAL" % (
            corrected_used_space / bytes_per_GB, disk_usage_info.total / bytes_per_GB)

        return "System Information:\n\t%s\n\t%s\n\t%s" % (cpu_info_string, memory_info_string, disk_usage_info_string)

    def getTotalElapsedTime(self) -> datetime.timedelta:
        currentTime = datetime.datetime.now()
        elapsed = currentTime - self.shared_test_objects.start_time
        return elapsed

    def getTestElapsedTime(self) -> Union[datetime.timedelta, str]:
        currentTime = datetime.datetime.now()
        if self.test_start_time is None:
            return "Cannot calculate yet - Splunk Instance(s) still being set up."
        elapsed = currentTime - self.test_start_time
        return elapsed

    def getTimeDeltaRoundedToNearestSecond(self, delta: Union[str, datetime.timedelta]) -> str:
        if isinstance(delta, str):
            return delta
        rounded_delta = datetime.timedelta(
            seconds=round(delta.total_seconds()))
        return str(rounded_delta)

    def getAverageTimePerTest(self) -> Union[str, datetime.timedelta]:
        elapsed = self.getTestElapsedTime()
        if isinstance(elapsed, str):
            return elapsed

        if self.shared_test_objects.result_count == 0:
            return "Cannot calculate yet - first test has not finished yet"

        average_time_per_test = elapsed / self.shared_test_objects.result_count
        rounded_time_string = self.getTimeDeltaRoundedToNearestSecond(
            average_time_per_test)

        return str(rounded_time_string)

    def getAverageTimeRemaining(self) -> str:
        avg = self.getAverageTimePerTest()

        if isinstance(avg, str):
            # We returned some string, which is a description as to why
            # we can't calculate the average (yet). Just return that
            return avg

        # multiply the remaining time by the number of tests
        total_time_remaining = avg * self.shared_test_objects.testing_queue.qsize()

        # return an approximation of the remaining time
        return self.getTimeDeltaRoundedToNearestSecond(total_time_remaining)

    def all_instances_ready(self):
        CHECKED_READY = True
        if CHECKED_READY and self.test_start_time is not None:
            return True
        elif CHECKED_READY and self.test_start_time is None:
            self.test_start_time = datetime.datetime.now()
            return True

        return False

    def summarize(self) -> str:

        try:
            # Get a summary of some system stats
            if self.config.target_infrastructure == DetectionTestingTargetInfrastructure.container:
                # We should also probably check that the IP is 127.0.0.1 as well?  But we will leave
                # this alone for now
                system_stats = self.get_system_stats()
            else:
                system_stats = None

            status_string = "***********PROGRESS UPDATE***********\n"
            if not self.all_instances_ready():
                status_string += f"\tWaiting for container setup: {self.getTimeDeltaRoundedToNearestSecond(self.getTotalElapsedTime())}\n"
                return status_string

            elapsed_time = self.getTimeDeltaRoundedToNearestSecond(
                self.getTotalElapsedTime())
            test_execution_time = self.getTimeDeltaRoundedToNearestSecond(
                self.getTestElapsedTime())
            estimated_time_remaining = self.getAverageTimeRemaining()
            tests_to_run = self.shared_test_objects.testing_queue.qsize()
            average_time_per_test = self.getTimeDeltaRoundedToNearestSecond(
                self.getAverageTimePerTest())
            tests_currently_running = "TO BE DETERMINED"
            tests_completed = self.shared_test_objects.result_count
            successes = self.shared_test_objects.pass_count
            failures = self.shared_test_objects.fail_count
            status_string += \
                f"\tElapsed Time               : {elapsed_time}\n"\
                f"\tTest Execution Time        : {test_execution_time}\n"\
                f"\tEstimated Remaining Time   : {estimated_time_remaining}\n"\
                f"\tTests to run               : {tests_to_run}\n"\
                f"\tAverage Time Per Test      : {average_time_per_test}\n"\
                f"\tTests currently running    : {tests_currently_running}\n"\
                f"\tTests completed            : {tests_completed}\n"\
                f"\t\tSuccesses : {successes}\n"\
                f"\t\tFailures  : {failures}\n"
            if status_string is not None:
                status_string += f"\t{system_stats}\n"

            return status_string

        except Exception as e:
            return f"Error in printing execution summary: [{str(e)}]"

    def checkFailures(self) -> bool:
        return False

    def run_instances(self) -> None:
        if self.config.target_infrastructure == DetectionTestingTargetInfrastructure.server:
            server = SplunkServer(self.config,
                                  self.shared_test_objects,
                                  WEB_PORT_START,
                                  HEC_PORT_START,
                                  MANAGEMENT_PORT_START)
            self.instances.append(server)
        elif self.config.target_infrastructure == DetectionTestingTargetInfrastructure.container:
            for container_number in range(self.config.num_containers):
                # MANAGEMENT_PORT and HEC_PORT are number*2 since they are right next
                # to each other and we don't want them to collide
                container = SplunkContainer(self.config,
                                            self.shared_test_objects,
                                            WEB_PORT_START,
                                            HEC_PORT_START,
                                            MANAGEMENT_PORT_START,
                                            self.files_to_copy_to_container,
                                            container_number=container_number)
                self.instances.append(container)

        for instance in self.instances:
            instance.thread.start()

    def run_status_thread(self) -> None:
        self.summary_thread.start()

    def queue_status_thread(self, status_interval: int = 60, num_steps: int = 10) -> None:

        while True:
            # This for loop lets us run the summarize print less often, but check for failure more often
            for chunk in range(0, status_interval, int(status_interval/num_steps)):
                if self.shared_test_objects.checkContainerFailure():
                    print(
                        "One of the containers has shut down prematurely or the test was halted. Ensuring all containers are stopped.")
                    for container in self.containers:
                        container.stopContainer()
                    print("All containers stopped")
                    self.all_tests_completed = False
                    return None
                time.sleep(status_interval/num_steps)

            at_least_one_container_has_started_running_tests = False
            for container in self.containers:
                if container.test_start_time != -1:
                    at_least_one_container_has_started_running_tests = True
                    break
            if self.shared_test_objects.summarize(testing_currently_active=at_least_one_container_has_started_running_tests) == False:
                # There are no more tests to run, so we can return from this thread
                self.all_tests_completed = True
                return None
