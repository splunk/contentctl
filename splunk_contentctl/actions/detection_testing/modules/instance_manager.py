from collections import OrderedDict
from tabnanny import check
import docker
import datetime
import docker.types
import os
import random

import json
import string
import time
import timeit

from typing import Union

from splunk_contentctl.actions.detection_testing.modules.splunk_instance import SplunkInstance, SplunkContainer, SplunkServer
from splunk_contentctl.actions.detection_testing.modules.shared_test_objects import SharedTestObjects
from splunk_contentctl.objects.enums import DetectionTestingTargetInfrastructure
from splunk_contentctl.objects.detection import Detection
from splunk_contentctl.objects.test_config import TestConfig
from splunk_contentctl.objects.enums import InstanceState

from tempfile import mkdtemp
import pathlib
import threading
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

        self.summary_thread = threading.Thread(
            target=self.queue_status_thread)
        

        #print("CODE TO GENERATE YOUR BASELINE INFORMATION HERE")

        # Construct the baseline from the splunk version and the apps to be installed
        #self.baseline = self.generate_baseline()

        self.instances: list[SplunkInstance] = []


        
        #Everything seems to have started okay with no exceptions, print he 
        print("\n\n***********************")
        print(f"Log into your [{self.config.num_containers}] Splunk Instance(s) after they are ready at http://{self.config.test_instance_address}:[{WEB_PORT_START}-{WEB_PORT_START + self.config.num_containers - 1}]")
        print(f"\tSplunk App Username: [{self.config.splunk_app_username}]")
        print(f"\tSplunk App Password: [{self.config.splunk_app_password}]")
        print("***********************\n\n")

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
        self.run_instances()
        
        self.summary_thread.start()
        
        self.summary_thread.join()



        for instance in self.instances:
            if self.shared_test_objects.noUntestedDetectionsRemain():
                instance.thread.join()
            else:
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
            print(f"Removing all attack data that was downloaded during this test at: [{self.shared_test_objects.attack_data_root_folder}]")
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
        if self.shared_test_objects.test_start_time is None:
            return "Cannot calculate yet - Splunk Instance(s) still being set up."
        elapsed = currentTime - self.shared_test_objects.test_start_time
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
    
        return average_time_per_test

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
        for instance in self.instances:
            if instance.testingStats.instance_state == InstanceState.starting:
                #This instance is ready, but we need to check the rest of them
                print(instance.testingStats.instance_state)
                return False
            else:
                #At least one instance is not ready
                pass

        return True

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
                status_string += f"\tWaiting for instance setup: {self.getTimeDeltaRoundedToNearestSecond(self.getTotalElapsedTime())}\n"
                return status_string

            elapsed_time = self.getTimeDeltaRoundedToNearestSecond(
                self.getTotalElapsedTime())
            test_execution_time = self.getTimeDeltaRoundedToNearestSecond(
                self.getTestElapsedTime())
            estimated_time_remaining = self.getAverageTimeRemaining()
            tests_to_run = self.shared_test_objects.testing_queue.qsize()
            average_time_per_test = self.getTimeDeltaRoundedToNearestSecond(
                self.getAverageTimePerTest())
            tests_completed = self.shared_test_objects.result_count
            successes = self.shared_test_objects.pass_count
            failures = self.shared_test_objects.fail_count
            status_string += \
                f"\tElapsed Time               : {elapsed_time}\n"\
                f"\tTest Execution Time        : {test_execution_time}\n"\
                f"\tEstimated Remaining Time   : {estimated_time_remaining}\n"\
                f"\tAverage Time Per Test      : {average_time_per_test}\n"\
                f"\tTests to run               : {tests_to_run}\n"\
                f"\tTests completed            : {tests_completed}\n"\
                f"\t\tSuccesses : {successes}\n"\
                f"\t\tFailures  : {failures}\n"
            if system_stats is not None:
                status_string += f"\t{system_stats}\n"

            return status_string

        except Exception as e:
            return f"Error in printing execution summary: [{str(e)}]"

    def atLeastOneInstanceErrored(self) -> bool:
        for instance in self.instances:
            if instance.testingStats.instance_state == InstanceState.error:
                return True
        #Nothing was in an error state
        return False
    

    def atLeastOneInstanceRunning(self):
        for instance in self.instances:
            if instance.testingStats.instance_state == InstanceState.starting or \
               instance.testingStats.instance_state == InstanceState.running or \
               instance.testingStats.instance_state == InstanceState.stopping :
                return True
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

        


    def force_finish(self):
        self.shared_test_objects.force_finish = True


    def queue_status_thread(self, status_interval: int = 60, num_steps: int = 30) -> None:        
        #This loop lets us frequently check to see if the testing
        #is complete but only print out status every once in a while
        check_interval = int(status_interval/num_steps)
        while self.atLeastOneInstanceRunning():
            for chunk in range(0, status_interval, check_interval):
                if not self.atLeastOneInstanceRunning():
                    break
                time.sleep(check_interval)
            print(self.summarize())
        
        return None



