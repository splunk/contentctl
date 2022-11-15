from collections import OrderedDict
import datetime
import docker
import docker.types
import docker.models
import docker.models.resource
import docker.models.containers
import os.path
import random
import requests
import xmltodict
from requests.auth import HTTPBasicAuth

from bin.detection_testing.modules import splunk_sdk, testing_service, test_driver
from bin.objects.test_config import TestConfig
import pathlib
import time
import timeit
from typing import Union
import threading
import wrapt_timeout_decorator
import sys
import traceback
import uuid
import requests
import splunklib.client as client
SPLUNKBASE_URL = "https://splunkbase.splunk.com/app/%d/release/%s/download"
SPLUNK_START_ARGS = "--accept-license"

#Give ten minutes to start - this is probably enough time
MAX_CONTAINER_START_TIME_SECONDS = 60*20

DEFAULT_EVENT_HOST = "ATTACK_DATA_HOST"
DEFAULT_DATA_INDEX = set(["main"])
FAILURE_SLEEP_INTERVAL_SECONDS = 60



class SplunkInstance:
    def __init__(
        self,
        config: TestConfig,
        synchronization_object: test_driver.TestDriver,
        web_port: int = 8000,
        management_port: int = 8089,
        hec_port: int = 8088,
        files_to_copy_to_instance = []
        #files_to_copy_to_container: OrderedDict = OrderedDict(),
        #mounts: list[docker.types.Mount] = [],
    ):
        
        self.config = config
        self.synchronization_object = synchronization_object
        
        self.web_port = web_port
        self.management_port = management_port
        self.hec_port = hec_port
        self.ports = [web_port, hec_port, management_port]
        
        
        
        self.files_to_copy_to_instance = files_to_copy_to_instance
        self.thread = threading.Thread(target=self.run_instance, )
        

    def get_service(self):
        try:
            service = client.connect(
                host=self.config.ip,
                port=self.management_port,
                username=self.config.splunk_app_username,
                password=self.config.splunk_app_password
            )
        except Exception as e:
            raise(Exception("Unable to connect to Splunk instance: " + str(e)))
        return service
    
    def test_detection(instance:SplunkInstance, detection:Detection, attack_data_root_folder)->bool:
        abs_folder_path = mkdtemp(prefix="DATA_", dir=attack_data_root_folder)
        success = execute_tests(instance, detection.testFile.tests, abs_folder_path)
        shutil.rmtree(abs_folder_path)
        detection.get_detection_result()
        #Delete the folder and all of the data inside of it
        #shutil.rmtree(abs_folder_path)
        return success
    
    def execute_tests(instance:SplunkInstance, tests:list[Test], attack_data_folder:str)->bool:
    
        success = True
        for test in tests:
            try:
                #Run all the tests, even if the test fails.  We still want to get the results of failed tests
                result = execute_test(instance, test, attack_data_folder)
                #And together the result of the test so that if any one test fails, it causes this function to return False                
                success &= result
            except Exception as e:
                raise(Exception(f"Unknown error executing test: {str(e)}"))
        return success



    def format_test_result(job_result:dict, testName:str, fileName:str, logic:bool=False, noise:bool=False)->dict:
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

    def hec_raw_replay(base_url:str, token:str, filePath:pathlib.Path, index:str, 
                    source:Union[str,None]=None, sourcetype:Union[str,None]=None, 
                    host:Union[str,None]=None, channel:Union[str,None]=None, 
                    use_https:bool=True, port:int=8088, verify=False, 
                    path:str="services/collector/raw", wait_for_ack:bool=True):
        
        if verify is False:
            #need this, otherwise every request made with the requests module
            #and verify=False will print an error to the command line
            disable_warnings()


        #build the headers
        if token.startswith('Splunk '):
            headers = {"Authorization": token} 
        else:
            headers = {"Authorization": f"Splunk {token}"} #token must begin with 'Splunk 
        
        if channel is not None:
            headers['X-Splunk-Request-Channel'] = channel
        
        
        #Now build the URL parameters
        url_params_dict = {"index": index}
        if source is not None:
            url_params_dict['source'] = source 
        if sourcetype is not None:
            url_params_dict['sourcetype'] = sourcetype
        if host is not None:
            url_params_dict['host'] = host 
        
        
        if base_url.lower().startswith('http://') and use_https is True:
            raise(Exception(f"URL {base_url} begins with http://, but use_http is {use_https}. "\
                            "Unless you have modified the HTTP Event Collector Configuration, it is probably enabled for https only."))
        if base_url.lower().startswith('https://') and use_https is False:
            raise(Exception(f"URL {base_url} begins with https://, but use_http is {use_https}. "\
                            "Unless you have modified the HTTP Event Collector Configuration, it is probably enabled for https only."))
        
        if not (base_url.lower().startswith("http://") or base_url.lower().startswith('https://')):
            if use_https:
                prepend = "https://"
            else:
                prepend = "http://"
            old_url = base_url
            base_url = f"{prepend}{old_url}"
            #print(f"Warning, the URL you provided {old_url} does not start with http:// or https://.  We have added {prepend} to convert it into {base_url}")
        

        #Generate the full URL, including the host, the path, and the params.
        #We can be a lot smarter about this (and pulling the port from the url, checking 
        # for trailing /, etc, but we leave that for the future)
        url_with_path = urllib.parse.urljoin(f"{base_url}:{port}", path)
        with open(filePath,"rb") as datafile:
            rawData = datafile.read()

        try:
            res = requests.post(url_with_path,params=url_params_dict, data=rawData, allow_redirects = True, headers=headers, verify=verify)
            #print(f"POST Sent with return code: {res.status_code}")
            jsonResponse = json.loads(res.text)
            #print(res.status_code)
            #print(res.text)
            
        except Exception as e:
            raise(Exception(f"There was an exception in the post: {str(e)}"))
        

        if wait_for_ack:
            if channel is None:
                raise(Exception("HEC replay WAIT_FOR_ACK is enabled but CHANNEL is None. Channel must be supplied to wait on ack"))
            
            if "ackId" not in jsonResponse:
                raise(Exception(f"key 'ackID' not present in response from HEC server: {jsonResponse}"))
            ackId = jsonResponse['ackId']
            url_with_path = urllib.parse.urljoin(f"{base_url}:{port}", "services/collector/ack")
            import timeit, time
            start = timeit.default_timer()
            j = {"acks":[jsonResponse['ackId']]}
            while True:            
                try:
                    
                    res = requests.post(url_with_path, json=j, allow_redirects = True, headers=headers, verify=verify)
                    #print(f"ACKID POST Sent with return code: {res.status_code}")
                    jsonResponse = json.loads(res.text)
                    #print(f"the type of ackid is {type(ackId)}")
                    if 'acks' in jsonResponse and str(ackId) in jsonResponse['acks']:
                        if jsonResponse['acks'][str(ackId)] is True:
                            break
                        else:
                            #print("Waiting for ackId")

                            time.sleep(2)

                    else:
                        print(url_with_path)
                        print(j)
                        print(headers)
                        raise(Exception(f"Proper ackID structure not found for ackID {ackId} in {jsonResponse}"))
                except Exception as e:
                    raise(Exception(f"There was an exception in the post: {str(e)}"))
                

    def replay_attack_data_files(instance:SplunkInstance, attackDataObjects:list[AttackData], attack_data_folder:str)->set[str]:
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
                test_indices.add(replay_attack_data_file(instance, attack_data_file, attack_data_folder))
            except Exception as e:
                raise(Exception(f"Error replaying attack data file {attack_data_file.data}: {str(e)}"))
        return test_indices



    def replay_attack_data_file(instance:SplunkInstance, attackData:AttackData, attack_data_folder:str)->str:
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
                print(f"copy from {attackData.data}-->{data_file}")
                shutil.copyfile(attackData.data, data_file)
            except Exception as e:
                raise(Exception(f"Unable to copy local attack data file {attackData.data} - {str(e)}"))
            
        
        else:
            #Download the file
            #We need to overwrite the file - mkstemp will create an empty file with the 
            #given name
            utils.download_file_from_http(attackData.data, data_file, overwrite_file=True) 
        
        # Update timestamps before replay
        if attackData.update_timestamp:
            data_manipulation = DataManipulation()
            data_manipulation.manipulate_timestamp(data_file, attackData.sourcetype,attackData.source)    

        #Get an session from the API
        service = get_service(instance)

            
        #Upload the data
        hec_raw_replay(instance.config.ip, instance.tokenString, pathlib.Path(data_file), attackData.index, attackData.source, attackData.sourcetype, splunk_sdk.DEFAULT_EVENT_HOST, channel=instance.channel, port=instance.hec_port)
        

        #Wait for the indexing to finish
        #print("skip waiting for ingest since we have checked the ackid")
        #if not splunk_sdk.wait_for_indexing_to_complete(splunk_ip, splunk_port, splunk_password, attackData.sourcetype, upload_index):
        #    raise Exception("There was an error waiting for indexing to complete.")
        
        #print('done waiting')
        #Return the name of the index that we uploaded to
        return attackData.index





    def test_detection_search(container:SplunkInstance, test:Test, attempts_remaining:int=4, 
                            failure_sleep_interval_seconds:int=FAILURE_SLEEP_INTERVAL_SECONDS, FORCE_ALL_TIME=True)->TestResult:
        
        #Since this is an attempt, decrement the number of remaining attempts
        attempts_remaining -= 1
        
        #remove leading and trailing whitespace from the detection.
        #If we don't do this with leading whitespace, this can cause
        #an issue with the logic below - mainly prepending "|" in front
        # of searches that look like " | tstats <something>"
        detectionFile = test.detectionFile
        search = detectionFile.search
        if search != detectionFile.search.strip():
            print(f"The detection contained in {detectionFile.name} contains leading or trailing whitespace.  Please update this search to remove that whitespace.")
            search = detectionFile.search.strip()
        
        if search.startswith('|'):
            updated_search = search
        else:
            updated_search = 'search ' + search 


        #Set the mode and timeframe, if required
        kwargs = {"exec_mode": "blocking"}
        if not FORCE_ALL_TIME:
            kwargs.update({"earliest_time": test.earliest_time,
                        "latest_time": test.latest_time})

        #Append the pass condition to the search
        splunk_search = f"{updated_search} {test.pass_condition}"

        try:
            service = get_service(container)
        except Exception as e:
            error_message = "Unable to connect to Splunk instance: %s"%(str(e))
            print(error_message,file=sys.stderr)
            return TestResult(generated_exception={"message":error_message})


        try:
            job = service.jobs.create(splunk_search, **kwargs)
            results_stream = job.results(output_mode='json')
            
            result =  TestResult(no_exception=job.content)


            if result.success == False:
                #The test did not work, so just return the failure
                return result
            
            #The test was successful, so check the observables, if applicable

            observables_to_check = set()
            #Should we include the extra notable observables here?

            for observable in test.detectionFile.observables:
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
                            print("Found all observables :)")
                            return result
                        if len(observables_always_found) == 0:
                            observables_always_found = found_observables
                        else:
                            observables_always_found = found_observables.intersection(observables_always_found)

                #If we get here, then we have not found a single result with all of the observables.  We will
                #return as part of the error all the fields which did not appear in ALL the results.
                
                result.missing_observables = list(observables_to_check - observables_always_found)
                print(f"Missing observable(s) for detection: {result.missing_observables}")
                
                return result

                        


        except Exception as e:
            error_message = "Unable to execute detection: %s"%(str(e))
            print(error_message,file=sys.stderr)
            return TestResult(generated_exception={"message":error_message})


        


    def delete_attack_data(container:SplunkInstance, indices:set[str], host:str=DEFAULT_EVENT_HOST)->bool:
        
        
        try:
            service = get_service(container)
        except Exception as e:

            raise(Exception("Unable to connect to Splunk instance: " + str(e)))


        #print(f"Deleting data for {detection_filename}: {indices}")
        for index in indices:
            while (get_number_of_indexed_events(container, index=index, event_host=host) != 0) :
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
    def execute_test(instance:SplunkInstance, test:Test, attack_data_folder:str)->bool:
        
        print(f"\tExecuting test {test.name}")
        #replay all of the attack data
        test_indices = replay_attack_data_files(instance, test.attack_data, attack_data_folder)

        import timeit, time
        start = timeit.default_timer()
        MAX_TIME = 120
        sleep_base = 2
        sleep_exp = 0
        while True:
            sleeptime = sleep_base**sleep_exp
            sleep_exp += 1
            #print(f"Sleep for {sleeptime} for ingest") 
            time.sleep(sleeptime)
            #Run the baseline(s) if they exist for this test
            execute_baselines(instance, test.baselines)
            if test.error_in_baselines() is True:
                #One of the baselines failed. No sense in running the real test
                #Note that a baselines which fail is different than a baselines which didn't return some results!
                test.result = TestResult(generated_exception={'message':"Baseline(s) failed"})
            elif test.all_baselines_successful() is False:
                #go back and run the loop again - no sense in running the detection search if the baseline didn't work successfully
                test.result = TestResult(generated_exception={'message':"Detection search did not run - baselines(s) failed"})
                #we set this as exception false because we don't know for sure there is an issue - we could just
                #be waiting for data to be ingested for the baseline to fully run. However, we don't have the info
                #to fill in the rest of the fields, so we populate it like we populate the fields when there is a real exception
                test.result.exception = False 
                
                
            else:
                #baselines all worked (if they exist) so run the search
                test.result = splunk_sdk.test_detection_search(instance, test)
            
            if test.result.success:
                #We were successful, no need to run again.
                break
            elif test.result.exception:
                #There was an exception, not just a failure to find what we're looking for. break 
                break
            elif timeit.default_timer() - start > MAX_TIME:
                break
            
        if instance.config.post_test_behavior == PostTestBehavior.always_pause or \
        (test.result.success == False and instance.config.post_test_behavior == PostTestBehavior.pause_on_failure):
        
            # The user wants to debug the test
            message_template = "\n\n\n****SEARCH {status} : Allowing time to debug search/data****\nPress ENTER to continue..."
            if test.result.success == False:
                # The test failed
                formatted_message = message_template.format(status="FAILURE")
                
            else:
                #The test passed 
                formatted_message = message_template.format(status="SUCCESS")

            #Just use this to pause on input, we don't do anything with the response
            print(f"DETECTION FILE: {test.detectionFile.path}")
            print(f"DETECTION SEARCH: {test.result.search}")
            _ = input(formatted_message)
            

        splunk_sdk.delete_attack_data(instance, indices = test_indices)
        
        #Return whether the test passed or failed
        return test.result.success



    def execute_baselines(instance:SplunkInstance, baselines:list[Test]):
        for baseline in baselines:
            execute_baseline(instance, baseline)
    
    

    def execute_baseline(instance:SplunkInstance, baseline:Test):
    
    
        baseline.result = splunk_sdk.test_detection_search(instance, baseline)


    def get_container_summary(self) -> str:
        current_time = timeit.default_timer()

        # Total time the container has been running
        if self.container_start_time == -1:
            total_time_string = "NOT STARTED"
        else:
            total_time_rounded = datetime.timedelta(
                seconds=round(current_time - self.container_start_time))
            total_time_string = str(total_time_rounded)

        # Time that the container setup took
        if self.test_start_time == -1 or self.container_start_time == -1:
            setup_time_string = "NOT SET UP"
        else:
            setup_secounds_rounded = datetime.timedelta(
                seconds=round(self.test_start_time - self.container_start_time))
            setup_time_string = str(setup_secounds_rounded)

        # Time that the tests have been running
        if self.test_start_time == -1 or self.num_tests_completed == 0:
            testing_time_string = "NO TESTS COMPLETED"
        else:
            testing_seconds_rounded = datetime.timedelta(
                seconds=round(current_time - self.test_start_time))

            # Get the approximate time per test.  This is a clunky way to get rid of decimal
            # seconds.... but it works
            timedelta_per_test = testing_seconds_rounded/self.num_tests_completed
            timedelta_per_test_rounded = timedelta_per_test - \
                datetime.timedelta(
                    microseconds=timedelta_per_test.microseconds)

            testing_time_string = "%s (%d tests @ %s per test)" % (
                testing_seconds_rounded, self.num_tests_completed, timedelta_per_test_rounded)

        summary_str = "Summary for %s\n\t"\
                      "Total Time          : [%s]\n\t"\
                      "Container Start Time: [%s]\n\t"\
                      "Test Execution Time : [%s]\n" % (
                          self.container_name, total_time_string, setup_time_string, testing_time_string)

        return summary_str

    def wait_for_splunk_ready(
        self,
        seconds_between_attempts: int = 10,
    ) -> bool:
                
        while True:
            try:
                service = splunk_sdk.client.connect(host=self.config.ip, port=self.management_port, username=self.config.splunk_app_username, password=self.config.splunk_app_password)
                if service.restart_required:
                    #The sleep below will wait
                    pass
                else:
                    return True
              
            except Exception as e:
                # There is a good chance the server is restarting, so the SDK connection failed.
                # Or, we tried to check restart_required while the server was restarting.  In the
                # calling function, we have a timeout, so it's okay if this function could get 
                # stuck in an infinite loop (the caller will generate a timeout error)
                pass
                    
            time.sleep(seconds_between_attempts)

    
    
    
    def configure_hec(self):
        try:

            auth = HTTPBasicAuth(self.config.splunkbase_username, self.config.splunk_app_password)
            address = f"https://{self.config.ip}:{self.management_port}/services/data/inputs/http"
            data = {
                "name": "DETECTION_TESTING_HEC",
                "index": "main",
                "indexes": "main,_internal,_audit", #this needs to support all the indexes in test files
                "useACK": True
            }
            import urllib3
            urllib3.disable_warnings()
            r = requests.get(address, data=data, auth=auth, verify=False)
            if r.status_code == 200:
                #Yes, this endpoint exists!
                asDict = xmltodict.parse(r.text)
                #Long, messy way to get the token we need. This could use more error checking for sure.
                self.tokenString = [m['#text'] for m in asDict['feed']['entry']['content']['s:dict']['s:key'] if '@name' in m and m['@name']=='token'][0]
                self.channel = str(uuid.uuid4())
                return
            
            #Otherwise no, the endpoint does not exist. Create it
            r = requests.post(address, data=data, auth=auth, verify=False)
            if r.status_code == 201:
                asDict = xmltodict.parse(r.text)
                #Long, messy way to get the token we need. This could use more error checking for sure.
                self.tokenString = [m['#text'] for m in asDict['feed']['entry']['content']['s:dict']['s:key'] if '@name' in m and m['@name']=='token'][0]
                self.channel = str(uuid.uuid4())
                return
                
            else:
                raise(Exception(f"Error setting up hec.  Response code from {address} was [{r.status_code}]: {r.text} "))
            
        except Exception as e:
            raise(Exception(f"There was an issue setting up HEC....{str(e)}"))
            
    


        
        
    def successfully_finish_tests(self)->None:
        try:
            if self.num_tests_completed == 0:
                print("Container [%s] did not find any tests and will not start.\n"\
                      "This does not mean there was an error!"%(self.container_name))
            else:
                print("Container [%s] has finished running [%d] detections, time to stop the container."
                      % (self.container_name, self.num_tests_completed))
            
            
            # remove the container
            self.removeContainer()
        except Exception as e:
            print(
                "Error stopping or removing the container: [%s]" % (str(e)))

        return None
    

    def run_instance(self) -> None:
        print("Starting the container [%s]" % (self.container_name))
        
        # Try to get something from the queue. Check this early on
        # before launching the container because it can save us a lot of time!
        detection_to_test = self.synchronization_object.getTest()
        if detection_to_test is None:
            return self.successfully_finish_tests()

        self.container_start_time = timeit.default_timer()
    
        container_start_time = timeit.default_timer()
        
        try:
            self.setup_container()
        except Exception as e:
            print("There was an exception starting the container [%s]: [%s].  Shutting down container"%(self.container_name,str(e)),file=sys.stdout)
            self.stopContainer()
            elapsed_rounded = round(timeit.default_timer() - container_start_time)
            time_string = (datetime.timedelta(seconds=elapsed_rounded))
            print("Container [%s] FAILED in [%s]"%(self.container_name, time_string))
            return None


        #GTive some info about how long the container took to start up
        elapsed_rounded = round(timeit.default_timer() - container_start_time)
        time_string = (datetime.timedelta(seconds=elapsed_rounded))
        print("Container [%s] took [%s] to start"%(self.container_name, time_string))
        self.synchronization_object.start_barrier.wait()


        # Sleep for a small random time so that containers drift apart and don't synchronize their testing
        time.sleep(random.randint(1, 30))
        self.test_start_time = timeit.default_timer()
        while detection_to_test is not None:
            if self.synchronization_object.checkContainerFailure():
                self.container.stop()
                print("Container [%s] successfully stopped early due to failure" % (self.container_name))
                return None

            current_test_start_time = timeit.default_timer()
            # Sleep for a small random time so that containers drift apart and don't synchronize their testing
            #time.sleep(random.randint(1, 30))
            
             
            # There is a detection to test
            
            print(f"Container [{self.container_name}]--->[{str(detection_to_test.detectionFile.path)}]")
            try:
                
                result = testing_service.test_detection(self, detection_to_test, self.synchronization_object.attack_data_root_folder)
                

                self.synchronization_object.addResult(detection_to_test)
                #self.synchronization_object.addResult(result, timeit.default_timer() - current_test_start_time)

                
            except Exception as e:
                print(
                    "Warning - uncaught error in detection test for [%s] - this should not happen: [%s]"
                    % (detection_to_test.testFile.path, str(e))
                )
                import traceback
                traceback.print_exc()
                try:
                    self.synchronization_object.addResult(detection_to_test)
                except Exception as e:
                    print(f"Adding a failed result to the queue failed with error: {str(e)}")
    
                ###begin testing block
                #self.num_tests_completed += 1

                # Try to get something from the queue
            
                #detection_to_test = self.synchronization_object.getTest()
                
                #continue
                ###end testing block
    
    
    
    
    
                #traceback.print_exc()
                #import pdb
                #pdb.set_trace()
                # Fill in all the "Empty" fields with default values. Otherwise, we will not be able to 
                # process the result correctly.  
                '''
                detection_to_test.replace("security_content/tests", "security_content/detections")
                try:
                    test_file_obj = testing_service.load_file(os.path.join("security_content/", detection_to_test))
                    if 'file' not in test_file_obj:
                        raise Exception(f"'file' field not found in {detection_to_test}")
                except:
                    test_file_obj['file'] = detection_to_test.replace("tests/", "").replace(".test.yml", ".yml")
                    print(f"Error getting the detection file associated with the test file. We will try our best to convert it: {detection_to_test}-->{test_file_obj['file']}")
                    

                self.synchronization_object.addError(
                    {"detection_file": test_file_obj['file'],
                        "detection_error": str(e)}, duration_string = datetime.timedelta(seconds=round(timeit.default_timer() - current_test_start_time))


                )
                '''
            self.num_tests_completed += 1

            # Try to get something from the queue
            detection_to_test = self.synchronization_object.getTest()
            
        #We failed to get a test from the queue, so we must be done gracefully!  Quit
        return self.successfully_finish_tests()



    def get_number_of_indexed_events(container:SplunkInstance, index:str, event_host:str=DEFAULT_EVENT_HOST, sourcetype:Union[str,None]=None )->int:

        try:
            service = get_service(container)
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
            
        


    def wait_for_indexing_to_complete(container:SplunkInstance, sourcetype:str, index:str, check_interval_seconds:int=5)->bool:
        startTime = timeit.default_timer()
        previous_count = -1
        time.sleep(check_interval_seconds)
        while True:
            new_count = get_number_of_indexed_events(container, index=index, sourcetype=sourcetype)
            #print(f"Previous Count [{previous_count}] New Count [{new_count}]")
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
    def __init__(self, config: TestConfig, synchronization_object: test_driver.TestDriver, web_port: int = 8000, management_port: int = 8089, hec_port: int = 8088, files_to_copy_to_instance=[]):
        super().__init__(config, synchronization_object, web_port, management_port, hec_port, files_to_copy_to_instance)

        SPLUNK_CONTAINER_APPS_DIR = "/opt/splunk/etc/apps"
        files_to_copy_to_container = OrderedDict()
        files_to_copy_to_container["INDEXES"] = {
            "local_file_path": os.path.join(self.config.repo_path,"bin/detection_testing/indexes.conf.tar"), "container_file_path": os.path.join(SPLUNK_CONTAINER_APPS_DIR, "search")}
        files_to_copy_to_container["DATAMODELS"] = {
            "local_file_path": os.path.join(self.config.repo_path,"bin/detection_testing/datamodels.conf.tar"), "container_file_path": os.path.join(SPLUNK_CONTAINER_APPS_DIR, "SPLUNK_SA_CIM")}
        files_to_copy_to_container["AUTHORIZATIONS"] = {
            "local_file_path": os.path.join(self.config.repo_path,"bin/detection_testing/authorizations.conf.tar"), "container_file_path": "/opt/splunk/etc/system/local"}
        

        self.mounts = [docker.types.Mount(os.path.abspath(os.path.join(self.config.repo_path,"apps")),
                                          "/tmp/apps",
                                          "bind",
                                          True)]
        


    def prepare_apps_path(self) -> tuple[str, bool]:
        apps_to_install = []
        require_credentials=False
        for app in self.config.apps:
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

    def make_ports(self, ports: list[int]) -> dict[str, int]:
        port_dict = {}
        for port in ports:
            port_dict[f"tcp/{port}"] = port
        return port_dict

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

        container = self.client.containers.create(
            self.config.full_image_path,
            ports=self.make_ports(self.ports),
            environment=self.make_environment(),
            name=self.config.container_name,
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
                % (local_file_path, self.container_name)
            )
        successful_copy = False
        api_client = docker.APIClient()
        # need to use the low level client to put a file onto a container
        while not successful_copy:
            try:
                with open(local_file_path, "rb") as fileData:
                    # splunk will restart a few times will installation of apps takes place so it will reload its indexes...

                    api_client.put_archive(
                        container=self.container_name,
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

    def stopContainer(self,timeout=10) -> bool:
        try:        
            container = self.client.containers.get(self.container_name)
            #Note that stopping does not remove any of the volumes or logs,
            #so stopping can be useful if we want to debug any container failure 
            container.stop(timeout=10)
            self.synchronization_object.containerFailure()
            return True

        except Exception as e:
            # Container does not exist, or we could not get it. Throw and error
            print("Error stopping docker container [%s]"%(self.container_name))
            return False
        

    def removeContainer(
        self, removeVolumes: bool = True, forceRemove: bool = True
    ) -> bool:
        try:
            container = self.client.containers.get(self.container_name)
        except Exception as e:
            # Container does not exist, no need to try and remove it
            return True
        try:
            # container was found, so now we try to remove it
            # v also removes volumes linked to the container
            container.remove(
                v=removeVolumes, force=forceRemove
            )
            # remove it even if it is running. remove volumes as well
            # No need to print that the container has been removed, it is expected behavior
            return True
        except Exception as e:
            print("Could not remove Docker Container [%s]" % (
                self.container_name))
            raise (Exception(f"CONTAINER REMOVE ERROR: {str(e)}"))


    #@wrapt_timeout_decorator.timeout(MAX_CONTAINER_START_TIME_SECONDS, timeout_exception=RuntimeError)
    def setup_container(self):
        
        self.container.start()


        # def shutdown_signal_handler(sig, frame):
        #     shutdown_client = docker.client.from_env()
        #     errorCount = 0
        
        #     print(f"Shutting down {self.container_name}...", file=sys.stderr)
        #     try:
        #         container = shutdown_client.containers.get(self.container_name)
        #         #Note that stopping does not remove any of the volumes or logs,
        #         #so stopping can be useful if we want to debug any container failure 
        #         container.stop(timeout=10)
        #         print(f"{self.container_name} shut down successfully", file=sys.stderr)        
        #     except Exception as e:
        #         print(f"Error trying to shut down {self.container_name}. It may have already shut down.  Stop it youself with 'docker containter stop {self.container_name}", sys.stderr)
            
            
        #     #We must use os._exit(1) because sys.exit(1) actually generates an exception which can be caught! And then we don't Quit!
        #     import os
        #     os._exit(1)
                

                    
        # import signal
        # signal.signal(signal.SIGINT, shutdown_signal_handler)

        # By default, first copy the index file then the datamodel file
        for file_description, file_dict in self.files_to_copy_to_container.items():
            self.extract_tar_file_to_container(
                file_dict["local_file_path"], file_dict["container_file_path"]
            )

        print("Finished copying files to [%s]" % (self.container_name))
        self.wait_for_splunk_ready()
        self.configure_hec()

class SplunkServer(SplunkInstance):
    pass            
