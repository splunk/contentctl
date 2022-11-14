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
SPLUNKBASE_URL = "https://splunkbase.splunk.com/app/%d/release/%s/download"
SPLUNK_START_ARGS = "--accept-license"

#Give ten minutes to start - this is probably enough time
MAX_CONTAINER_START_TIME_SECONDS = 60*20





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

class SplunkContainer(SplunkInstance):
    def __init__(self, config: TestConfig, synchronization_object: test_driver.TestDriver, web_port: int = 8000, management_port: int = 8089, hec_port: int = 8088, files_to_copy_to_instance=[]):
        super().__init__(config, synchronization_object, web_port, management_port, hec_port, files_to_copy_to_instance)





    def prepare_mounts(self)->dict:
        return {}

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
