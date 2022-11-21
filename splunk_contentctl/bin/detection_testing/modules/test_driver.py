import copy
import csv
import datetime
import json
import os
import queue
import shutil
import sys
import tempfile
import threading
import time
import timeit
from collections import OrderedDict
from typing import Union

import psutil
from bin.detection_testing import summarize_json

import pathlib
import yaml


from bin.objects.test_config import TestConfig
from bin.objects.detection import Detection
from bin.detection_testing.modules.test_objects import ResultsManager
from bin.objects.enums import DetectionTestingTargetInfrastructure








class TestDriver:
    def __init__(self, detections:list[Detection], config: TestConfig):
        #Create the queue and enque all of the tests
        self.testing_queue = queue.Queue()
        for test in detections:
            self.testing_queue.put(test)
        
        self.total_number_of_tests = self.testing_queue.qsize()
        #Creates a lock that will be used to synchronize access to this object
        
        self.total_start_time = datetime.datetime.now()
        self.test_start_time:Union[None, datetime.datetime] = None

        self.results = queue.Queue()
        self.container_ready_time = None
        
        #No containers have failed
        self.container_failure = False

        #Just make a random folder to store attack data that we donwload
        self.attack_data_root_folder = tempfile.mkdtemp(prefix="attack_data_", dir=os.getcwd())
        print("Attack data for this run will be stored at: [%s]"%(self.attack_data_root_folder))
        
        #Not used right now, but we will keep it around for a bit in case we want to use it again
        self.start_barrier = threading.Barrier(config.num_containers)

        #The config that will be used for writing out the error config reproduction fiel
        self.summarization_reproduce_failure_config = copy.deepcopy(config)


        #According to the docs:
        # Warning the first time this function is called with interval = 0.0 or None it will return a meaningless 0.0 value which you are supposed to ignore.
        # We call this exactly once here to prime for future calls and throw away the result
        _ = psutil.cpu_times_percent(percpu=False)
        self.config = config
        self.resultsManager = ResultsManager()


    def getDetection(self)-> Union[Detection,None]:
        
        try:
            return self.testing_queue.get(block=False)
        except Exception as e:
            return None
        
    def outputResultsCSV(self, field_names:list[str], output_filename:str, data:list[dict], baseline:OrderedDict)->bool:
        print("Generating %s..."%(output_filename), end='')
        
        try:                        
            with open(output_filename, 'w') as csvfile:
                header_writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
                for key in baseline:
                    #Very basic support for pretty pritning dicts. Doesn't handle more than 1 nested dict
                    if type(baseline[key]) is OrderedDict:
                        header_writer.writerow([key, "-"])
                        for nestedkey in baseline[key]:
                            header_writer.writerow([nestedkey, baseline[key][nestedkey]])
                    #Basic support for 1 layer nested list. Doesn't handle more than 1.
                    elif type(baseline[key]) is list and len(baseline[key])>0:
                        header_writer.writerow([key, baseline[key][0]])
                        for i in range(1,len(baseline[key])):
                            header_writer.writerow(['-', baseline[key][i]])
                        
                    else:
                        header_writer.writerow([key, baseline[key]])
                header_writer.writerow(['',''])
                csv_writer = csv.DictWriter(csvfile, fieldnames=field_names)
                csv_writer.writeheader()
                for row in data:
                    csv_writer.writerow(row)
            print("Done with [%d] detections"%(len(data)))

        except Exception as e:
            print("Failure writing to CSV file for [%s]:"%(output_filename, str(e)))
            return False

        return True

    

    def finish(self):
        self.cleanup()
        if self.resultsManager.pass_count == self.total_number_of_tests:
            return True
        return False

        
    def cleanup(self):
        
        try:
            print("Removing all attack data that was downloaded during this test at: [%s]"%(self.attack_data_root_folder))
            shutil.rmtree(self.attack_data_root_folder)
            print("Successfully removed all attack data")
        finally:
            pass

    def get_system_stats(self)->str:
        # System stats are only useful in some cases (when Splunk is running locally)
        
        
        bytes_per_GB = 1024 * 1024 * 1024
        cpu_info = psutil.cpu_times_percent(percpu=False)
        memory_info = psutil.virtual_memory()
        disk_usage_info = psutil.disk_usage('/')

        #macOS is really weird about disk usage.... so to get free space we use TOTAL-FREE = USED instead of just USED
        corrected_used_space = disk_usage_info.total - disk_usage_info.free

        cpu_info_string =        "Total CPU Usage   : %d%% (%d CPUs)"%(100 - cpu_info.idle, psutil.cpu_count(logical=False))
        memory_info_string =     "Total Memory Usage: %0.1fGB USED / %0.1fGB TOTAL"%((memory_info.total - memory_info.available) / bytes_per_GB, memory_info.total / bytes_per_GB)
        disk_usage_info_string = "Total Disk Usage  : %0.1fGB USED / %0.1fGB TOTAL"%(corrected_used_space / bytes_per_GB, disk_usage_info.total / bytes_per_GB)
        
        return "System Information:\n\t%s\n\t%s\n\t%s"%(cpu_info_string, memory_info_string, disk_usage_info_string)


    def getTotalElapsedTime(self)->datetime.timedelta:
        currentTime = datetime.datetime.now()
        elapsed = currentTime - self.total_start_time

        return elapsed
    
    def getTestElapsedTime(self)->Union[datetime.timedelta,str]:
        currentTime = datetime.datetime.now()
        if self.test_start_time is None:
            return "Cannot calculate yet - Splunk Instance(s) still being set up."
        elapsed = currentTime - self.test_start_time
        return elapsed
    
    def getTimeDeltaRoundedToNearestSecond(self, delta: Union[str,datetime.timedelta])->str:
        if isinstance(delta, str):
            return delta
        rounded_delta = datetime.timedelta(seconds = round(delta.total_seconds()))
        return str(rounded_delta)


    def getAverageTimePerTest(self)->Union[str,datetime.timedelta]:
        elapsed = self.getTestElapsedTime()
        if isinstance(elapsed,str):
            return elapsed
        
        num_tests_completed = self.resultsManager.result_count
        if  num_tests_completed == 0:
            return "Cannot calculate yet - first test has not finished yet"
        
        average_time_per_test = elapsed / num_tests_completed
        rounded_time_string = self.getTimeDeltaRoundedToNearestSecond(average_time_per_test)

        return str(rounded_time_string)
    
    def getAverageTimeRemaining(self)->str:
        avg = self.getAverageTimePerTest()
        
        if isinstance(avg,str):
            #We returned some string, which is a description as to why
            #we can't calculate the average (yet). Just return that
            return avg

        #multiply the remaining time by the number of tests
        total_time_remaining = avg * self.testing_queue.qsize()
        #return an approximation of the remaining time
        return self.getTimeDeltaRoundedToNearestSecond(total_time_remaining)


        
    def all_instances_ready(self):
        CHECKED_READY = True
        if CHECKED_READY and self.test_start_time is not None:
            return True
        elif CHECKED_READY and self.test_start_time is None:
            self.test_start_time = datetime.datetime.now()
            return True
        
        return False
        

    def summarize(self)->str:
        
        try:
            #Get a summary of some system stats
            if self.config.target_infrastructure == DetectionTestingTargetInfrastructure.container:
                #We should also probably check that the IP is 127.0.0.1 as well?  But we will leave
                #this alone for now
                system_stats=self.get_system_stats()
            else:
                system_stats = None
            
            
            
            status_string = "***********PROGRESS UPDATE***********\n"
            if not self.all_instances_ready():
                status_string += f"\tWaiting for container setup: {self.getTimeDeltaRoundedToNearestSecond(self.getTotalElapsedTime())}\n"
                return status_string
            
            
            
            elapsed_time = self.getTimeDeltaRoundedToNearestSecond(self.getTotalElapsedTime())
            test_execution_time = self.getTimeDeltaRoundedToNearestSecond(self.getTestElapsedTime())
            estimated_time_remaining = self.getAverageTimeRemaining()
            tests_to_run = self.testing_queue.qsize()
            average_time_per_test = self.getTimeDeltaRoundedToNearestSecond(self.getAverageTimePerTest())
            tests_currently_running = "TO BE DETERMINED"
            tests_completed = self.resultsManager.pass_count + self.resultsManager.fail_count
            successes = self.resultsManager.pass_count
            failures = self.resultsManager.fail_count
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
        
    def addResult(self, detection:Detection):
        self.resultsManager.addCompletedDetection(detection)
        
