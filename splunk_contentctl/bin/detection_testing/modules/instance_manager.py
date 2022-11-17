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
from bin.detection_testing.modules import splunk_instance, test_driver
from bin.objects.enums import DetectionTestingTargetInfrastructure
from bin.objects.detection import Detection
from bin.objects.test_config import TestConfig


WEB_PORT_START = 8000
HEC_PORT_START = 8088
MANAGEMENT_PORT_START = 8089

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


class InstanceManager:
    def __init__(self,
                config: TestConfig,
                detection_list: list[Detection],
                files_to_copy_to_container: OrderedDict = OrderedDict()):

        self.jobStats = JobStats()
        self.config = config
        #Used to determine whether or not we should wait for container threads to finish when summarizing
        self.all_tests_completed = False

        self.synchronization_object = test_driver.TestDriver(detection_list, config)
        self.files_to_copy_to_container = files_to_copy_to_container
        
    
        
        print("\n\n***********************")
        print(f"Log into your [{self.config.num_containers}] Splunk Instance(s) after they boot at http://127.0.0.1:[{WEB_PORT_START}-{WEB_PORT_START + self.config.num_containers - 1}]")
        print("\tSplunk App Username: [%s]"%("admin"))
        print("\tSplunk App Password: ", end='')
        
        print("[%s]"%(self.config.splunk_app_password))
        
        print("***********************\n\n")
        

        if self.config.target_infrastructure == DetectionTestingTargetInfrastructure.container:
            print("start and set up some containers")
        else:
            print("it's just a server that is already set up")
        
        

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
        
        self.instances:list[splunk_instance.SplunkInstance] = []

    def run_test(self)->bool:
        self.run_status_thread()
        self.run_instances()
        self.summary_thread.join()
        
        
        

            
        for instance in self.instances:
            if self.all_tests_completed == True:
                instance.thread.join()
            elif self.all_tests_completed == False:
                #For some reason, we stopped early.  So don't wait on the child threads to finish. Don't join,
                #these threads may be stuck in their setup loops. Continue on.
                pass
            
            print("Output the summary at the end")
            #print(instance.get_container_summary())
            
        print("All containers completed testing!")
        
        
        
        
        self.jobStats.setStopTime()
        self.baseline['TEST_START_TIME'] = self.jobStats.startTime
        self.baseline['TEST_FINISH_TIME'] =  self.jobStats.stopTime
        
        
        self.baseline['TEST_DURATION'] = self.jobStats.getTotalTime()

        return self.synchronization_object.finish(self.baseline)




    def run_instances(self) -> None:
        if self.config.target_infrastructure == DetectionTestingTargetInfrastructure.server:
            server = splunk_instance.SplunkServer(self.config, 
                                                  self.synchronization_object, 
                                                  WEB_PORT_START, 
                                                  HEC_PORT_START,
                                                  MANAGEMENT_PORT_START)
            self.instances.append(server)
        elif self.config.target_infrastructure == DetectionTestingTargetInfrastructure.container:
            for container_number in range(self.config.num_containers):
                #MANAGEMENT_PORT and HEC_PORT are number*2 since they are right next
                #to each other and we don't want them to collide
                container = splunk_instance.SplunkContainer(self.config, 
                                                            self.synchronization_object, 
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
        





    

    def queue_status_thread(self, status_interval:int=60, num_steps:int=10)->None:
        print("queue status thread, just exit")
        import sys
        sys.exit(1)
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
            
