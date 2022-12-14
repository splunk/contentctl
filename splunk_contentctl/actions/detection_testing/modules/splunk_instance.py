from __future__ import annotations
#Only used for static typing. We need this to avoid circular import warning
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from splunk_contentctl.actions.detection_testing.modules.instance_manager import SharedTestObjects

from collections import OrderedDict
import datetime
import docker
import docker.types
import docker.models
import docker.models.resource
import docker.models.containers
from docker.models.resource import Model
import os.path

import requests

from requests.auth import HTTPBasicAuth
from tempfile import mkdtemp, mkstemp
from shutil import rmtree, copyfile

import pathlib
import time
import timeit
from typing import Union
import threading
#import wrapt_timeout_decorator
import sys
import traceback

import json
import uuid
import requests
import splunklib.client as client
import splunklib.results as results
from urllib3 import disable_warnings
import urllib.parse

from splunk_contentctl.helper.utils import Utils
from splunk_contentctl.actions.detection_testing.modules.DataManipulation import DataManipulation

from splunk_contentctl.objects.test_config import TestConfig
from splunk_contentctl.objects.enums import PostTestBehavior
from splunk_contentctl.objects.detection import Detection
from splunk_contentctl.objects.unit_test_test import UnitTestTest
from splunk_contentctl.objects.unit_test_baseline import UnitTestBaseline
from splunk_contentctl.objects.unit_test_attack_data import UnitTestAttackData
from splunk_contentctl.objects.unit_test_result import UnitTestResult
from splunk_contentctl.objects.enums import InstanceState




SPLUNKBASE_URL = "https://splunkbase.splunk.com/app/%d/release/%s/download"
SPLUNK_START_ARGS = "--accept-license"

#Give ten minutes to start - this is probably enough time
MAX_CONTAINER_START_TIME_SECONDS = 60*20

DEFAULT_EVENT_HOST = "ATTACK_DATA_HOST"
DEFAULT_DATA_INDEX = set(["main"])
FAILURE_SLEEP_INTERVAL_SECONDS = 60



class TestingStats:
    num_detections_tested:int = 0
    instance_start_time:datetime.datetime = datetime.datetime.now()
    instance_stop_time:Union[datetime.datetime,None] = None
    testing_start_time:Union[datetime.datetime,None] = None
    testing_stop_time:Union[datetime.datetime,None] = None
    instance_state: InstanceState = InstanceState.stopped
    
    instance_state:InstanceState
    
    def __init__(self):
        self.num_detections_tested = 0
        self.instance_state = InstanceState.running
        self.instance_start_time = datetime.datetime.now()
        self.testing_start_time = datetime.datetime.now()
    
    def begin(self):
        self.__init__()
    
    def getAvgTimePerDetection(self)->str:
        delta = self.getElapsedTestingTime()
        if self.num_detections_tested == 0:
            return "No Detections Completed Yet..."
        time_per_test = delta / self.num_detections_tested
        time_per_test_rounded = time_per_test - datetime.timedelta(microseconds=time_per_test.microseconds)
        return str(time_per_test_rounded)
    
    def getElapsedTime(self)->datetime.timedelta:
        if self.instance_stop_time is None:
            #Still running so use current time
            delta = datetime.datetime.now() - self.instance_start_time
        else:
            delta = self.instance_stop_time - self.instance_start_time
        return delta
    
    def getElapsedTestingTime(self)->datetime.timedelta:
        if self.testing_start_time is None:
            raise(Exception("Cannot get elapsed time for testing - testing has not begun yet"))
        if self.testing_stop_time is None:
            #Still running so use current time
            delta = datetime.datetime.now() - self.testing_start_time
        else:
            delta = self.testing_stop_time - self.testing_start_time
        return delta    
    
    def addTest(self):
        self.num_detections_tested += 1

    def setInstanceState(self, instanceState:InstanceState):
        #In the cases below, we will want to update some timers
        if self.instance_state == InstanceState.starting and instanceState == InstanceState.running:
            self.testing_start_time = datetime.datetime.now()
        elif self.instance_state == InstanceState.running and instanceState in [InstanceState.error, InstanceState.stopped, InstanceState.stopping]:
            self.testing_stop_time = datetime.datetime.now()
        
        if self.instance_state != InstanceState.stopped and instanceState == InstanceState.stopped:
            self.instance_stop_time = datetime.datetime.now()
        self.instance_state = instanceState
    
        






class SplunkInstance:
    def __init__(
        self,
        config: TestConfig,
        shared_test_objects: SharedTestObjects,
        web_port: int = 8000,
        hec_port: int = 8088,
        management_port: int = 8089,
        files_to_copy_to_instance: OrderedDict = OrderedDict()):
        
        
        self.config = config
        self.shared_test_objects = shared_test_objects
        self.web_port = web_port
        self.management_port = management_port
        self.hec_port = hec_port

        
        self.testingStats = TestingStats()
        #self.process = multiprocessing.Process(target=self.run, )
        self.thread = threading.Thread(target=self.run, )
        self.files_to_copy_to_instance = files_to_copy_to_instance

        #use print at the default output....for now
        self.custom_print = print
        self.print_verbosity = 0

    def print(self, content:str):
        self.custom_print(f"[{self.get_name()}]: {content}")

    def get_name(self)->str:
        return self.config.test_instance_address
    

    def get_service(self):
        try:
            service = client.connect(
                host=self.config.test_instance_address,
                port=self.management_port,
                username=self.config.splunk_app_username,
                password=self.config.splunk_app_password
            )
        except Exception as e:
            raise(Exception(f"Unable to connect to Splunk instance at [{self.config.test_instance_address}]: {str(e)}"))
        return service
    
    

    def test_detection(self, detection:Detection, attack_data_root_folder)->bool:
        if detection.test is None:
            self.print(f"No unit tests found found for {detection.name}")
            return False
        abs_folder_path = mkdtemp(prefix="DATA_", dir=attack_data_root_folder)
        
        success = self.execute_tests(detection, abs_folder_path)
        
        if success:
            #no need to be extremely verbose and print out everything
            beginning = f"[{detection.name} --> PASSES: {len(detection.test.tests)}]"
        else:
            beginning = f"[{detection.name} --> FAIL (FAILURES: {detection.get_num_failed_tests()}, PASSES: {detection.get_num_successful_tests()})]"

        
        summaries = []
        at_least_one_test_missing_observables = False
        for test in detection.test.tests:    
            if test.result is None:
                summaries.append(f"'{test.name}' - TEST NOT RUN FOR UNKNOWN REASON")
            else:
                #print out all the results if at least one of the detections is misisng an observable
                at_least_one_test_missing_observables |= len(test.result.missing_observables) > 0
                summaries.append(f"{test.result.get_summary(test.name)}")
        
        if success == False or at_least_one_test_missing_observables:
            total_summary = "\n\t******************".join(summaries)
            self.print(f"{beginning}\n\t{total_summary}\n")
        else:
            self.print(f"{beginning}")
        
        

        #Delete the temp folder and data inside of it
        rmtree(abs_folder_path)
        return success
    
    def execute_tests(self, detection:Detection, attack_data_folder:str)->bool:
    
        success = True
        for test in detection.test.tests:
            try:
                #Run all the tests, even if the test fails.  We still want to get the results of failed tests
                result = self.execute_test(detection, test, attack_data_folder)
                #And together the result of the test so that if any one test fails, it causes this function to return False                
                success &= result
            except Exception as e:
                raise(Exception(f"Unknown error executing test: {str(e)}"))
        return success



    def format_test_result(self, job_result:dict, testName:str, fileName:str, logic:bool=False, noise:bool=False)->dict:
        testResult = {
            "name": testName,
            "file": fileName,
            "logic": logic,
            "noise": noise,
        }


        if 'status' in job_result:
            #Test failed, no need for further processing
            testResult['status'] = job_result['status']
        
        
            
        else:
        #Mark whether or not the test passed
            if job_result['eventCount'] == 1:
                testResult["status"] = True
            else:
                testResult["status"] = False


        JOB_FIELDS = ["runDuration", "scanCount", "eventCount", "resultCount", "performance", "search", "message"]
        #Populate with all the fields we want to collect
        for job_field in JOB_FIELDS:
            if job_field in job_result:
                testResult[job_field] = job_result.get(job_field, None)
        
        return testResult

    def hec_raw_replay(self, filePath:pathlib.Path, index:str, 
                    source:Union[str,None]=None, sourcetype:Union[str,None]=None, 
                    host:Union[str,None]=DEFAULT_EVENT_HOST, use_https:bool=True, verify_ssl=False, 
                    path:str="services/collector/raw", wait_for_ack:bool=True):
        
        if verify_ssl is False:
            #need this, otherwise every request made with the requests module
            #and verify=False will print an error to the command line
            disable_warnings()


        #build the headers

        if self.tokenString.startswith('Splunk '):
            headers = {"Authorization": self.tokenString} 
        else:
            headers = {"Authorization": f"Splunk {self.tokenString}"} #token must begin with 'Splunk 
        
        if self.channel is not None:
            headers['X-Splunk-Request-Channel'] = self.channel
        
        
        #Now build the URL parameters
        url_params_dict = {"index": index}
        if source is not None:
            url_params_dict['source'] = source 
        if sourcetype is not None:
            url_params_dict['sourcetype'] = sourcetype
        if host is not None:
            url_params_dict['host'] = host 
        
        
        if self.config.test_instance_address.lower().startswith('http://') and use_https is True:
            raise(Exception(f"URL {self.config.test_instance_address} begins with http://, but use_http is {use_https}. "\
                            "Unless you have modified the HTTP Event Collector Configuration, it is probably enabled for https only."))
        if self.config.test_instance_address.lower().startswith('https://') and use_https is False:
            raise(Exception(f"URL {self.config.test_instance_address} begins with https://, but use_http is {use_https}. "\
                            "Unless you have modified the HTTP Event Collector Configuration, it is probably enabled for https only."))
        
        if not (self.config.test_instance_address.lower().startswith("http://") or self.config.test_instance_address.lower().startswith('https://')):
            if use_https:
                prepend = "https://"
            else:
                prepend = "http://"
            
            base_url = f"{prepend}{self.config.test_instance_address}"
        else:
            base_url = self.config.test_instance_address
            
        

        #Generate the full URL, including the host, the path, and the params.
        #We can be a lot smarter about this (and pulling the port from the url, checking 
        # for trailing /, etc, but we leave that for the future)
        url_with_path = urllib.parse.urljoin(f"{base_url}:{self.hec_port}", path)
        with open(filePath,"rb") as datafile:
            rawData = datafile.read()

        try:
            res = requests.post(url_with_path,params=url_params_dict, data=rawData, allow_redirects = True, headers=headers, verify=verify_ssl)
            jsonResponse = json.loads(res.text)
            
            
            
        except Exception as e:
            raise(Exception(f"There was an exception sending attack_data to HEC: {str(e)}"))
        

        if wait_for_ack:
            if self.channel is None:
                raise(Exception("HEC replay WAIT_FOR_ACK is enabled but CHANNEL is None. Channel must be supplied to wait on ack"))
            
            if "ackId" not in jsonResponse:
                raise(Exception(f"key 'ackID' not present in response from HEC server: {jsonResponse}"))
            ackId = jsonResponse['ackId']
            url_with_path = urllib.parse.urljoin(f"{base_url}:{self.hec_port}", "services/collector/ack")
            
            start = timeit.default_timer()
            requested_acks = {"acks":[jsonResponse['ackId']]}
            while True:            
                try:
                    
                    res = requests.post(url_with_path, json=requested_acks, allow_redirects = True, headers=headers, verify=verify_ssl)
                    
                    jsonResponse = json.loads(res.text)
                    
                    if 'acks' in jsonResponse and str(ackId) in jsonResponse['acks']:
                        if jsonResponse['acks'][str(ackId)] is True:
                            #ackID has been found for our request, we can return as the data has been replayed
                            return
                        else:
                            #ackID is not yet true, we will wait some more
                            time.sleep(2)

                    else:
                        raise(Exception(f"Proper ackID structure not found for ackID {ackId} in {jsonResponse}"))
                except Exception as e:
                    raise(Exception(f"There was an exception in the post: {str(e)}"))
                

    def replay_attack_data_files(self, attackDataObjects:list[UnitTestAttackData], attack_data_folder:str)->set[str]:
        """Replay all attack data files into a splunk server as part of testing a detection. Note that this does not catch
        any exceptions, they should be handled by the caller

        Args:
            splunk_ip (str): ip address of the splunk server to target
            splunk_port (int): port of the splunk server API
            splunk_password (str): password to the splunk server
            attack_data_files (list[dict]): A list of dicts containing information about the attack data file
            attack_data_folder (str): The folder for downloaded or copied attack data to reside
        """
        test_indices = set()
        for attack_data_file in attackDataObjects:
            try:
                test_indices.add(self.replay_attack_data_file(attack_data_file, attack_data_folder))
            except Exception as e:
                raise(Exception(f"Error replaying attack data file {attack_data_file.data}: {str(e)}"))
        return test_indices


    
    def replay_attack_data_file(self, attackData:UnitTestAttackData, attack_data_folder:str)->str:
        """Function to replay a single attack data file. Any exceptions generated during executing
        are intentionally not caught so that they can be caught by the caller.

        Args:
            splunk_ip (str): ip address of the splunk server to target
            splunk_port (int): port of the splunk server API
            splunk_password (str): password to the splunk server
            attack_data_file (dict): a dict containing information about the attack data file
            attack_data_folder (str): The folder for downloaded or copied attack data to reside

        Returns:
            str: index that the attack data has been replayed into on the splunk server
        """
        #Get the index we should replay the data into
        
        
        descriptor, data_file = mkstemp(prefix="ATTACK_DATA_FILE_", dir=attack_data_folder)
        if not (attackData.data.startswith("https://") or attackData.data.startswith("http://")):
            #raise(Exception(f"Attack Data File {attack_data_file['file_name']} does not start with 'https://'. "  
            #                 "In the future, we will add support for non https:// hosted files, such as local files or other files. But today this is an error."))
            
            #We need to do this because if we are working from a file, we can't overwrite/modify the original during a test. We must keep it intact.
            try:
                copyfile(attackData.data, data_file)
            except Exception as e:
                raise(Exception(f"Unable to copy local attack data file {attackData.data} - {str(e)}"))
            
        
        else:
            #Download the file
            #We need to overwrite the file - mkstemp will create an empty file with the 
            #given name
            Utils.download_file_from_http(attackData.data, data_file, overwrite_file=True) 
        
        # Update timestamps before replay
        if attackData.update_timestamp:
            data_manipulation = DataManipulation()
            data_manipulation.manipulate_timestamp(data_file, attackData.sourcetype,attackData.source)    

        
    
        #Upload the data
        self.hec_raw_replay(pathlib.Path(data_file), attackData.custom_index, attackData.source, attackData.sourcetype)
        

        #Wait for the indexing to finish
        #print("skip waiting for ingest since we have checked the ackid")
        #if not splunk_sdk.wait_for_indexing_to_complete(splunk_ip, splunk_port, splunk_password, attackData.sourcetype, upload_index):
        #    raise Exception("There was an error waiting for indexing to complete.")
        
        #print('done waiting')
        #Return the name of the index that we uploaded to
        return attackData.custom_index





    def test_detection_search(self, detection:Detection, test:Union[UnitTestTest,UnitTestBaseline], FORCE_ALL_TIME=True)->UnitTestResult:
        
        
        
        #remove leading and trailing whitespace from the detection.
        #If we don't do this with leading whitespace, this can cause
        #an issue with the logic below - mainly prepending "|" in front
        # of searches that look like " | tstats <something>"
        
        search = detection.search
        if search != detection.search.strip():
            #self.print(f"The detection contained in {detection.file_path} contains leading or trailing whitespace.  Please update this search to remove that whitespace.")
            search = detection.search.strip()
        
        if search.startswith('|'):
            updated_search = search
        else:
            updated_search = 'search ' + search 


        #Set the mode and timeframe, if required
        kwargs = {"exec_mode": "blocking"}
        if not FORCE_ALL_TIME:
            if test.earliest_time is not None:  
                kwargs.update({"earliest_time": test.earliest_time})
            if test.latest_time is not None:
                kwargs.update({"latest_time": test.latest_time})
        

        #Append the pass condition to the search
        splunk_search = f"{updated_search} {test.pass_condition}"

        try:
            service = self.get_service()
        except Exception as e:
            error_message = "Unable to connect to Splunk instance: %s"%(str(e))
            self.print(error_message)
            return UnitTestResult(job_content=None, missing_observables=[], message=error_message)


        try:
            
            job = service.jobs.create(splunk_search, **kwargs)
            
            
            result = UnitTestResult(job_content=job.content)
            try:
                #This will fail if an exception is raised during the search
                _ = job.results(output_mode='json')
            except Exception as e:
                #There was an exception raised during the search, so we 
                #will return that to the user
                if result.message != None:
                    #Do nothing - the error was already captured in the result
                    pass
                else:
                    #add this to the messages for the result.
                    
                    result.add_message(f"Error(s) running search: {str(e)}")
                
                return result
                

            
            result = UnitTestResult(job_content=job.content)
            
            if result.success == False:
                #The test did not work, so just return the failure.  We may try to run
                #this search again because we might just not be done ingesting and
                #processing the initial data
                return result
            
            #The test was successful, so check the observables, if applicable
            observables_to_check = set()
            #Should we include the extra notable observables here?
            
            for observable in detection.tags.observable:
                name = observable.get("name",None)
                if name is None:
                    raise(Exception(f"Error checking observable {observable} - Name was None"))
                else:
                    observables_to_check.add(name)
            if len(observables_to_check) > 0:
                observable_splunk_search = f"{updated_search} | table {' '.join(observables_to_check)}"
                observable_job = service.jobs.create(observable_splunk_search, **kwargs)
                
                observable_results_stream = observable_job.results(output_mode='json')
                
                

                #Iterate through all of the results and ensure at least one contains non-null/empty 
                #values for all the fields we need
                observables_always_found =set()
                for res in observable_results_stream:
                    resJson = json.loads(res)
                    
                    for jsonResult in resJson.get("results",[]):
                        #Check that all of the fields exist and have non-null/non-empty string values
                        found_observables = set([observable for observable in observables_to_check if ( observable in jsonResult and jsonResult[observable] != None and jsonResult[observable] != "") ])
                        if len(observables_to_check.symmetric_difference(found_observables)) == 0:
                            result.missing_observables = []
                            return result
                        if len(observables_always_found) == 0:
                            observables_always_found = found_observables
                        else:
                            observables_always_found = found_observables.intersection(observables_always_found)

                #If we get here, then we have not found a single result with all of the observables.  We will
                #return as part of the error all the fields which did not appear in ALL the results.
                
                result.update_missing_observables(observables_to_check - observables_always_found)
                
                
                
            return result

                        


        except Exception as e:
            error_message = "Unable to execute detection: %s"%(str(e))
            self.print(error_message)
            return UnitTestResult(job_content=None, missing_observables=[], message=error_message)


        


    def delete_attack_data(self, indices:set[str], host:str=DEFAULT_EVENT_HOST)->bool:
        
        
        try:
            service = self.get_service()
        except Exception as e:

            raise(Exception("Unable to connect to Splunk instance: " + str(e)))


        
        for index in indices:
            while (self.get_number_of_indexed_events(index=index) != 0) :
                splunk_search = f'search index="{index}" host="{host}" | delete'
                kwargs = {
                        "exec_mode": "blocking"}
                try:
                    
                    job = service.jobs.create(splunk_search, **kwargs)
                    results_stream = job.results(output_mode='json')
                    reader = results.JSONResultsReader(results_stream)


                except Exception as e:
                    raise(Exception(f"Trouble deleting data using the search {splunk_search}: {str(e)}"))
            
        
        return True
    def execute_test(self, detection:Detection, test:UnitTestTest, attack_data_folder:str)->bool:
        
        
        #replay all of the attack data
        test_indices = self.replay_attack_data_files(test.attack_data, attack_data_folder)

        
        start = timeit.default_timer()
        MAX_TIME = 60
        #Fibonacci sequence is a good way to determine how long to sleep.
        #It concentrates shorter sleeps at the beginning while growing
        #wait time at a reasonable rate. The other good option is x^2
        
        #These defaults make the first sleep time 3
        sleep_time_0 = 1
        sleep_time_1 = 2

        while True:
            if timeit.default_timer() - start > MAX_TIME:
                #We ran out of time
                break

            sleeptime = sleep_time_0 + sleep_time_1
            sleep_time_0 = sleep_time_1
            sleep_time_1 = sleeptime
            
            time.sleep(sleeptime)
            #Run the baseline(s) if they exist for this test
            try:
                
                result = self.execute_baselines(detection, test)
                if result is None:
                    #There were no baselines, do nothing
                    pass
                elif result.exception:
                    # There was an actual exception generated while running the baseline.
                    # No sense in trying the baseline again
                    result.add_message("Did not execute detection because of Baseline Failure.")
                    test.result = result

                    break
                elif result.success:
                    #great, all of the baselines ran and were successful.
                    pass

                else:
                    #go back and run the loop again - no sense in running the detection search if the baseline didn't work successfully
                    test.result = result
                    #we set this as exception false because we don't know for sure there is an issue - we could just
                    #be waiting for data to be ingested for the baseline to fully run. However, we don't have the info
                    #to fill in the rest of the fields, so we populate it like we populate the fields when there is a real exception
                    continue
            except Exception as e:
                error_message = f"Unhandled error while executing baseline(s) for [{detection.file_path}] - {str(e)}"
                test.result = UnitTestResult(job_content=None, message=error_message)
                self.delete_attack_data(indices = test_indices)
                return False
                
                
                
            
            #If we get here, baselines all worked (if they exist) so run the search
            test.result = self.test_detection_search(detection, test)
            

            if test.result.determine_success():
                #We were successful, no need to run again. 
                break
            elif test.result.exception:
                #There was an exception, not just a failure to find what we're looking for break 
                break
            else:
                #We still have some time left, we will just run through the loop again
                continue
        
        if test.result is None:
            #We should not have gotten here without test.result being assigned
            test.result = UnitTestResult(job_content=None, message="Failed to produce a test result for unknown reason")

        if self.config.post_test_behavior == PostTestBehavior.always_pause or \
        (test.result.success == False and self.config.post_test_behavior == PostTestBehavior.pause_on_failure):
        
            # The user wants to debug the test
            message_template = "\n\n\n****SEARCH {status} : Allowing time to debug search/data****\nPress ENTER to continue..."
            if test.result.success == False:
                # The test failed
                formatted_message = message_template.format(status="FAILURE")
                
            else:
                #The test passed 
                formatted_message = message_template.format(status="SUCCESS")

            #Just use this to pause on input, we don't do anything with the response
            self.print(f"FILE: {detection.file_path}")
            sid = test.result.get_job_field('sid')
            link = f"http://{self.config.test_instance_address}:{self.web_port}/en-US/app/search/search?sid={sid}"
            if sid is not None:
                self.print(f"LINK: {link}")
            search = test.result.get_job_field('search')
            if search is None:
                search = "Unknown error getting search"
            if test.result.message is not None:
                self.print(f"MESSAGE: {test.result.message}")
            self.print(f"SEARCH:\n{search}")
            _ = input(formatted_message)
            

        self.delete_attack_data(indices = test_indices)
        
        #Return whether the test passed or failed
        return test.result.success



    def execute_baselines(self, detection:Detection, unit_test:UnitTestTest)->Union[UnitTestResult,None]:
        result = None
                
        for baseline in unit_test.baselines:
            result = self.execute_baseline(detection, baseline)
            if not result.success:
                #Return the first baseline that failed
                return result

        #If we got here, then there were no failures! Just return the last result
        return result
    
    

    def execute_baseline(self, detection:Detection, baseline:UnitTestBaseline)->UnitTestResult:
    
        #Treat a baseline just like a UnitTestTest - that's basically what it is!
        result = self.test_detection_search(detection, baseline)
        return result


    
    def configure_hec(self):
        
        if self.shared_test_objects.force_finish:
            return

        self.channel = str(uuid.uuid4())
        try:
            res = self.get_service().input(path='/servicesNS/nobody/splunk_httpinput/data/inputs/http/http:%2F%2FDETECTION_TESTING_HEC')
            self.tokenString = res.token
            self.print(f"HEC Endpoint for [{self.get_name()}] already exists with token [{self.tokenString}].  Using channel [{self.channel}]")
            return
        except Exception as e:
            #HEC input does not exist.  That's okay, we will create it
            #self.print(f"HEC ENDPOINT DOES NOT EXIST: {str(e)}")
            pass
        
        try:
            inputs = client.Inputs(self.get_service())
            created_input = inputs.create(name="DETECTION_TESTING_HEC", kind="http", index= "main", indexes = "main,_internal,_audit", useACK=True)
            self.tokenString = created_input.token
            self.print(f"Successfully configured HEC Endpoint for [{self.get_name()}] with channel [{self.channel}] and token [{self.tokenString}]")
            return


        except Exception as e:
            raise(Exception(f"Failure creating HEC Endpoint: {str(e)}"))
                

    def setup(self)->None:
        self.wait_for_splunk_ready()
        self.configure_hec()
        self.testingStats.begin()
        return None        
    
    def teardown(self)->None:

        if self.shared_test_objects.force_finish == True:
            self.print(f"Finishing due to error or cancellation after testing [{self.testingStats.num_detections_tested}] detections.")
        elif self.testingStats.num_detections_tested == 0 :
            self.print(f"Did not find any tests and will not start.")
        else:
            self.print(f"Finished testing [{self.testingStats.num_detections_tested}] detections.")
        self.testingStats.setInstanceState(InstanceState.stopped)
        return None

    def run(self):
        try:
            self.testingStats.setInstanceState(InstanceState.starting)
            self.setup()
            self.shared_test_objects.start_barrier.wait()
            self.testingStats.setInstanceState(InstanceState.running)
            detection_to_test = self.shared_test_objects.getDetection()
            while detection_to_test is not None:
                try:
                    success = self.test_detection(detection_to_test, self.shared_test_objects.attack_data_root_folder)
                except Exception as e:
                    self.print(f"Unhandled exception while testing detection [{detection_to_test.file_path}]: {str(e)}")
                    import traceback
                    traceback.print_exc()
                    success = False
                
                self.testingStats.addTest()
                self.shared_test_objects.addCompletedDetection(detection_to_test)
                #Get the next detection to test. If there are no more detections to test,
                #or there is an issue and one of the instance(s) is no longer running,
                #then this will return None
                detection_to_test = self.shared_test_objects.getDetection()
        except Exception as e:
            print(f"Exception while running test: {str(e)}")
            self.shared_test_objects.force_finish = True

        finally:
            print("finally")
            self.teardown()
    
    def wait_for_splunk_ready(
        self,
        seconds_between_attempts: int = 10, max_wait_time_seconds: int=0
    ) -> bool:
        #Wait time of zero is appropriate for SplunkServer.  Containers may take much longer

        start_time = datetime.datetime.now()

        self.print("Waiting for Splunk Instance Web Interface to come up...")
        while True:
            if self.shared_test_objects.force_finish:
                return True
            timediff = datetime.datetime.now() - start_time


            try:
                service = self.get_service()
                if service.restart_required:
                    #The sleep below will wait
                    pass
                else:
                    self.print(f"Splunk Interface is ready")
                    return True
              
            except Exception as e:
                # There is a good chance the server is restarting, so the SDK connection failed.
                # Or, we tried to check restart_required while the server was restarting.  In the
                # calling function, we have a timeout, so it's okay if this function could get 
                # stuck in an infinite loop (the caller will generate a timeout error)
                pass

            if max_wait_time_seconds == 0:
                raise(Exception(f"Unable to contact Splunk Instance - if this is a Splunk Server ensure that the address, ports, and credentials are correct and that the server is currently running - [{str(e)}]"))                    
            if timediff.total_seconds() > max_wait_time_seconds:
                raise(Exception(f"Unable to connect to Splunk Instance - Exceeded maximum start time of {max_wait_time_seconds}"))                    
            
            time.sleep(seconds_between_attempts)
        
            

    



    def get_number_of_indexed_events(self, index:str, event_host:str=DEFAULT_EVENT_HOST, sourcetype:Union[str,None]=None )->int:

        try:
            service = self.get_service()
        except Exception as e:
            raise(Exception("Unable to connect to Splunk instance: " + str(e)))

        if sourcetype is not None:
            search = f'''search index="{index}" sourcetype="{sourcetype}" host="{event_host}" | stats count'''
        else:
            search = f'''search index="{index}" host="{event_host}" | stats count'''
        kwargs = {"exec_mode":"blocking"}
        try:
            job = service.jobs.create(search, **kwargs)
    
            #This returns the count in string form, not as an int. For example:
            #OrderedDict([('count', '59630')])
            results_stream = job.results(output_mode='json')
            count = None
            num_results = 0
            for res in results.JSONResultsReader(results_stream):
                num_results += 1
                if isinstance(res, dict) and 'count' in res:
                    count = int(res['count'],10)
            if count is None:
                raise Exception(f"Expected the get_number_of_indexed_events search to only return 1 count, but got {num_results} instead.")
            
            return count    

        except Exception as e:
            raise Exception("Error trying to get the count while waiting for indexing to complete: %s"%(str(e)))
            
        


    def wait_for_indexing_to_complete(self, sourcetype:str, index:str, check_interval_seconds:int=5)->bool:
        startTime = timeit.default_timer()
        previous_count = -1
        time.sleep(check_interval_seconds)
        while True:
            new_count = self.get_number_of_indexed_events(index=index, sourcetype=sourcetype)
            
            if previous_count == -1:
                previous_count = new_count
            else:
                if new_count == previous_count:
                    stopTime = timeit.default_timer()
                    return True
                else:
                    previous_count = new_count
            
            #If new_count is really low, then the server is taking some extra time to index the data.
            # So sleep for longer to make sure that we give time to complete (or at least process more
            # events so we don't return from this function prematurely) 
            if new_count < 2:
                time.sleep(check_interval_seconds*3)
            else:
                time.sleep(check_interval_seconds)

class SplunkContainer(SplunkInstance):
        
    def __init__(self, config: TestConfig,
                 shared_test_objects: SharedTestObjects,
                 web_port: int = 8000,
                 hec_port: int = 8088,
                 management_port: int = 8089,
                 files_to_copy_to_instance: OrderedDict = OrderedDict(), container_number:int=0):

        
        web_port = web_port + container_number
        hec_port = hec_port + 2*container_number
        management_port = management_port + 2*container_number
        super().__init__(config, shared_test_objects, web_port, hec_port, management_port)
        self.ports={
            "8000/tcp":web_port,
            "8088/tcp":hec_port,
            "8089/tcp":management_port,
        }
        
        self.container_name = config.container_name % container_number
        

        SPLUNK_CONTAINER_APPS_DIR = "/opt/splunk/etc/apps"

        self.files_to_copy_to_instance["INDEXES"] = {
            "local_file_path": os.path.join(os.path.dirname(__file__), "../", "indexes.conf.tar"), "container_file_path": os.path.join(SPLUNK_CONTAINER_APPS_DIR, "search")}
        self.files_to_copy_to_instance["DATAMODELS"] = {
            "local_file_path": os.path.join(os.path.dirname(__file__), "../", "datamodels.conf.tar"), "container_file_path": os.path.join(SPLUNK_CONTAINER_APPS_DIR, "Splunk_SA_CIM")}
        self.files_to_copy_to_instance["AUTHORIZATIONS"] = {
            "local_file_path": os.path.join(os.path.dirname(__file__), "../", "authorize.conf.tar"), "container_file_path": "/opt/splunk/etc/system/local"}
        

        self.mounts = [docker.types.Mount(source=os.path.abspath(os.path.join(pathlib.Path('.'),"apps")),
                                          target="/tmp/apps",
                                          type="bind",
                                          read_only=True)]
        
        self.environment = self.make_environment()
        self.container = self.make_container()
        


    def teardown(self):
        self.testingStats.setInstanceState(InstanceState.stopping)
        self.stopContainer()
        self.removeContainer()
        super().teardown()

    def wait_for_splunk_ready(
        self,
        seconds_between_attempts: int = 10, max_wait_time_seconds: int=0
    ) -> bool:
        MAX_CONTAINER_SETUP_WAIT_TIME_SECONDS = 600
        return super().wait_for_splunk_ready(max_wait_time_seconds=600)

    def get_name(self)->str:
        return self.container_name

    def prepare_apps_path(self) -> tuple[str, bool]:
        apps_to_install = []
        require_credentials=False
        for app in self.config.apps:
            #import pprint
            #pprint.pprint(app.__dict__)
            if app.local_path is not None:
                filepath = pathlib.Path(app.local_path)
                #path to the mount in the docker container
                apps_to_install.append(os.path.join("/tmp/apps", filepath.name))
            elif app.http_path is not None:
                apps_to_install.append(app.http_path)
            elif app.splunkbase_path is not None:
                apps_to_install.append(app.splunkbase_path)
                require_credentials = True
            else:
                raise(Exception(f"No local, http, or Splunkbase path found for app {app.title}"))

        return ",".join(apps_to_install), require_credentials

    def make_environment(self) -> dict:
        env = {}
        env["SPLUNK_START_ARGS"] = SPLUNK_START_ARGS
        env["SPLUNK_PASSWORD"] = self.config.splunk_app_password
        splunk_apps_url, require_credentials = self.prepare_apps_path()

        if require_credentials:
            env["SPLUNKBASE_USERNAME"] = self.config.splunkbase_username
            env["SPLUNKBASE_PASSWORD"] = self.config.splunkbase_password
        env["SPLUNK_APPS_URL"] = splunk_apps_url
        
        return env

    

    def __str__(self) -> str:
        container_string = (
            f"Container Name: '{self.container_name}'\n\t"
            f"Docker Hub Path: '{self.config.full_image_path}'\n\t"
            f"Apps: '{self.environment['SPLUNK_APPS_URL']}'\n\t"
            f"Ports: {[self.web_port, self.hec_port, self.management_port]}\n\t"
            f"Mounts: {self.mounts}\n\t")

        return container_string

    def make_container(self) -> docker.models.resource.Model:
        # First, make sure that the container has been removed if it already existed
        self.removeContainer()

        
        
        container = self.get_client().containers.create(
            self.config.full_image_path,
            ports=self.ports,
            environment=self.make_environment(),
            name=self.get_name(),
            mounts=self.mounts,
            detach=True,
        )

        return container

    def extract_tar_file_to_container(
        self, local_file_path: str, container_file_path: str, sleepTimeSeconds: int = 5
    ) -> bool:
        # Check to make sure that the file ends in .tar.  If it doesn't raise an exception
        if os.path.splitext(local_file_path)[1] != ".tar":
            raise Exception(
                "Error - Failed copy of file [%s] to container [%s].  Only "
                "files ending in .tar can be copied to the container using this function."
                % (local_file_path, self.get_name())
            )
        successful_copy = False
        api_client = docker.APIClient()
        # need to use the low level client to put a file onto a container
        while not successful_copy:
            #Help bail from the install quickly if we have stopped the test
            if self.shared_test_objects.force_finish:
                return successful_copy

            try:
                with open(local_file_path, "rb") as fileData:
                    # splunk will restart a few times will installation of apps takes place so it will reload its indexes...

                    api_client.put_archive(
                        container=self.get_name(),
                        path=container_file_path,
                        data=fileData,
                    )
                    successful_copy = True
            except Exception as e:
                #print("Failed copy of [%s] file to [%s] on CONTAINER [%s]: [%s]\n...we will try again"%(local_file_path, container_file_path, self.container_name, str(e)))
                time.sleep(10)
                successful_copy = False
        #print("Successfully copied [%s] to [%s] on [%s]"% (local_file_path, container_file_path, self.container_name))
        return successful_copy

    def get_client(self):
        try:
            c = docker.client.from_env()
            
            
            return c
        except Exception as e:
            raise(Exception(f"Failed to get docker client: {str(e)}"))

    def stopContainer(self,timeout=10) -> bool:
        try:        
            
            
            self.testingStats.setInstanceState(InstanceState.stopping)
            self.print(f"Stopping container")
            container:docker.models.containers.Container = self.get_client().containers.get(self.get_name())
            #Note that stopping does not remove any of the volumes or logs,
            #so stopping can be useful if we want to debug any container failure 
            container.stop(timeout=timeout)
            self.print("Container successfully stopped")
            self.testingStats.setInstanceState(InstanceState.stopped)
            return True

        except Exception as e:
            # Container does not exist, or we could not get it. Throw and error
            self.print("Error stopping docker container")
            return False
        
        finally:
            #Consider it to be stopped, not errored
            self.testingStats.setInstanceState(InstanceState.stopped)
        

    def removeContainer(
        self, removeVolumes: bool = True, forceRemove: bool = True
    ) -> bool:
        
        try:
            container:docker.models.containers.Container = self.get_client().containers.get(self.get_name())
        except Exception as e:
            # Container does not exist, no need to try and remove it
            return True
        try:
            self.print("Removing container")
            # container was found, so now we try to remove it
            # v also removes volumes linked to the container
            container.remove(
                v=removeVolumes, force=forceRemove
            )
            # remove it even if it is running. remove volumes as well
            # No need to print that the container has been removed, it is expected behavior
            self.print("Container removed")
            return True
        except Exception as e:
            self.print("Could not remove Docker Container")
                
            raise (Exception(f"CONTAINER REMOVE ERROR: {str(e)}"))
        finally:
            #Consider it to be stopped, not errored
            self.testingStats.setInstanceState(InstanceState.stopped)



    #@wrapt_timeout_decorator.timeout(MAX_CONTAINER_START_TIME_SECONDS, timeout_exception=RuntimeError)
    def setup(self):
        
        self.testingStats.setInstanceState(InstanceState.starting)
        self.container.start()
        self.print(f"Starting container and installing [{len(self.config.apps)}] apps/TAs...")
        
        
        for file_description, file_dict in self.files_to_copy_to_instance.items():

            self.extract_tar_file_to_container(
                file_dict["local_file_path"], file_dict["container_file_path"]
            )

        self.print("Finished copying files to container")
        
        #call the superclass setup
        super().setup()        
    
class SplunkServer(SplunkInstance):
    pass            
