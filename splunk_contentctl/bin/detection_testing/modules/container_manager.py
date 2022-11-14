from collections import OrderedDict
from tabnanny import check
import docker
import datetime
import docker.types
import os
import random


import string
import threading
import time
import timeit

from typing import Union
from bin.detection_testing.modules import splunk_container, test_driver, utils

from bin.objects.test_config import TestConfig

WEB_PORT_STRING = "8000/tcp"
HEC_PORT_STRING = "8088/tcp"
MANAGEMENT_PORT_STRING = "8089/tcp"

#Keep track of time, at the very least, and maybe some other things
class JobStats:
    def __init__(self):
        self.startTime = datetime.datetime.now()
        self.stopTime = None
        self.totalTime = None
    def setStopTime(self):
        self.stopTime = datetime.datetime.now() 
        self.totalTime  = self.stopTime - self.startTime 
    def getElapsedTime(self):
        return  self.roundDurationToWholeSeconds(datetime.datetime.now() - self.startTime)
    def getTotalTime(self):
        if self.stopTime == None:
            return f"CANNOT GET TOTAL TIME - TEST STILL RUNNING FOR {self.getElapsedTime()}"
        else:
            return self.roundDurationToWholeSeconds(self.stopTime - self.startTime)
    def roundDurationToWholeSeconds(self, duration:datetime.timedelta):
        return str(duration - datetime.timedelta(microseconds=duration.microseconds))


class ContainerManager:
    def __init__(
        self,
        test_list: list[Detection],
        config: TestConfig,
        files_to_copy_to_container: OrderedDict = OrderedDict(),
        web_port_start: int = 8000,
        management_port_start: int = 8089,
        hec_port_start: int = 8088,
        mounts: list[dict[str, str]] = []):


        self.jobStats = JobStats()


        self.config = config
        #Used to determine whether or not we should wait for container threads to finish when summarizing
        self.all_tests_completed = False

        self.synchronization_object = test_driver.TestDriver(test_list, config)
        self.mounts = self.create_mounts(mounts)
    
        
        print("\n\n***********************")
        print(f"Log into your [{self.config.num_containers}] Splunk Container(s) after they boot at http://127.0.0.1:[{web_port_start}-{web_port_start + self.config.num_containers - 1}]")
        print("\tSplunk App Username: [%s]"%("admin"))
        print("\tSplunk App Password: ", end='')
        
        print("[%s]"%(self.config.splunk_app_password))
        
        print("***********************\n\n")
        

        self.containers = self.create_containers(web_port_start,
                                                 management_port_start,
                                                 hec_port_start,
                                                 files_to_copy_to_container)

        self.summary_thread = threading.Thread(target=self.queue_status_thread,args=())


        print("CODE TO GENERATE YOUR BASELINE INFORMATION HERE")
        
        
        #Construct the baseline from the splunk version and the apps to be installed
        self.baseline = OrderedDict()
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


    def run_test(self)->bool:
        self.run_status_thread()
        self.run_containers()
        self.summary_thread.join()
        
        
            
            
        for container in self.containers:
            if self.all_tests_completed == True:
                container.thread.join()
            elif self.all_tests_completed == False:
                #For some reason, we stopped early.  So don't wait on the child threads to finish. Don't join,
                #these threads may be stuck in their setup loops. Continue on.
                pass
            
            print(container.get_container_summary())
        print("All containers completed testing!")
        
        
        
        
        self.jobStats.setStopTime()
        self.baseline['TEST_START_TIME'] = self.jobStats.startTime
        self.baseline['TEST_FINISH_TIME'] =  self.jobStats.stopTime
        
        
        self.baseline['TEST_DURATION'] = self.jobStats.getTotalTime()

        return self.synchronization_object.finish(self.baseline)




    def run_containers(self) -> None:
         for container_number, container in enumerate(self.containers):
            #give a little time between container startup if there is more than one container.
            #Never wait on the first container. This gets us to testing as fast as possible
            #for the most common case (one container) and gives us some extra time and
            #reduces load when we are launching more than one container
            if (container_number != 0):
                time.sleep(10)
            container.thread.start()
        
    
    def run_status_thread(self) -> None:
        self.summary_thread.start()
        


    def create_containers(
        self,
        web_port_start: int,
        management_port_start: int,
        hec_port_start: int,
        files_to_copy_to_container: OrderedDict = OrderedDict(),
    ) -> list[splunk_container.SplunkContainer]:

        new_containers = []
        for index in range(self.config.num_containers):
            container_name = self.config.container_name % index
            web_port_tuple = (WEB_PORT_STRING, web_port_start + index)
            management_port_tuple = (MANAGEMENT_PORT_STRING, management_port_start + 2*index)
            hec_port_tuple = (HEC_PORT_STRING, hec_port_start + 2*index)
            
            new_containers.append(
                splunk_container.SplunkContainer(
                    self.config,
                    self.synchronization_object,
                    container_name,
                    web_port_tuple,
                    management_port_tuple,
                    hec_port_tuple,
                    files_to_copy_to_container,
                    self.mounts
                )
            )

        return new_containers

    def create_mounts(
        self, mounts: list[dict[str, str]]
    ) -> list[docker.types.Mount]:
        new_mounts = []
        for mount in mounts:
            new_mounts.append(self.create_mount(mount))
        return new_mounts

    def create_mount(self, mount: dict[str, str]) -> docker.types.Mount:
        return docker.types.Mount(
            source=os.path.abspath(mount["local_path"]),
            target=mount["container_path"],
            type=mount["type"],
            read_only=mount["read_only"],
        )

    

    def queue_status_thread(self, status_interval:int=60, num_steps:int=10)->None:

        while True:
            #This for loop lets us run the summarize print less often, but check for failure more often
            for chunk in range(0, status_interval, int(status_interval/num_steps)):
                if self.synchronization_object.checkContainerFailure():
                    print("One of the containers has shut down prematurely or the test was halted. Ensuring all containers are stopped.")
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
            if self.synchronization_object.summarize(testing_currently_active = at_least_one_container_has_started_running_tests) == False:
                #There are no more tests to run, so we can return from this thread
                self.all_tests_completed = True
                return None
            
