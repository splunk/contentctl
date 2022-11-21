import copy
import os
import random
import shutil
import docker
import sys

from collections import OrderedDict
from datetime import datetime
from posixpath import basename
from tempfile import mkdtemp
from timeit import default_timer as timer
from typing import Union
from urllib.parse import urlparse
import signal
import pathlib

import requests



from bin.detection_testing.modules import instance_manager
from bin.objects.detection import Detection
from bin.helper.utils import Utils
from bin.objects.test_config import TestConfig
from bin.detection_testing.modules.github_service import GithubService
from bin.objects.enums import PostTestBehavior, DetectionTestingMode
from bin.input.director import DirectorOutputDto
import yaml



CONTAINER_APP_DIRECTORY = "apps"
MOCK_DIRECTORY = "mock_directory"






def copy_local_apps_to_directory(config: TestConfig):
    
    if config.mock:
        shutil.rmtree(MOCK_DIRECTORY, ignore_errors=True)

    try:
        # Make sure the directory exists.  If it already did, that's okay. Don't delete anything from it
        # We want to re-use previously downloaded apps
        os.makedirs(CONTAINER_APP_DIRECTORY, exist_ok = True)
        
    except Exception as e:
        raise(Exception(f"Some error occured when trying to make the {CONTAINER_APP_DIRECTORY}: [{str(e)}]"))

    
    for app in config.apps:
    
        if app.must_download_from_splunkbase == False:
            if app.local_path is not None:
                if app.local_path == os.path.join(CONTAINER_APP_DIRECTORY, pathlib.Path(app.local_path).name):
                    print(f"same file {app.local_path}, skip...")
                else:
                    shutil.copy(app.local_path, os.path.join(CONTAINER_APP_DIRECTORY, pathlib.Path(app.local_path).name))
            elif app.http_path:
                filename = pathlib.Path(urlparse(app.http_path).path).name #get the filename from the url
                download_path = os.path.join(CONTAINER_APP_DIRECTORY, filename)
                Utils.download_file_from_http(app.http_path, download_path, verbose_print=True)
                app.local_path = download_path
            else:
                raise(Exception(f"Could not download {app.title}, not http_path or local_path or Splunkbase Credentials provided"))
        
        else:
            #no need to do anything, the containers will download from splunkbase
            pass
    '''
    apps_to_download = [app for app in config.apps if app.must_download_from_splunkbase == True]
    if len(apps_to_download) > 0:
        print(f"Found {len(apps_to_download)} apps that we must download from Splunkbase....")
        from external_libraries.download_splunkbase.download_splunkbase import download_all_apps
        try:
            download_all_apps(config.splunkbase_username, config.splunkbase_password, apps_to_download, pathlib.Path(CONTAINER_APP_DIRECTORY))
        except Exception as e:
            import traceback
            print(traceback.format_exc())
            sys.exit(1)
        print("done")
    '''







def finish_mock(config: TestConfig, detections: list[Detection], output_file_template: str = "prior_config/config_tests_%d.json")->bool:
    print("THIS IS A MOCK RUN AND MOCK IS NOT YET SUPPORTED")
    sys.exit(1)
    num_containers = config.num_containers

    #convert the list of Detection objects into a list of filename strings
    detection_filesnames = [str(d.detectionFile.path) for d in detections]
    
    for output_file_index in range(0, num_containers):
        fname = output_file_template % (output_file_index)

        # Get the n'th detection for this file
        detection_tests = detection_filesnames[output_file_index::num_containers]
        normalized_detection_names = []
        # Normalize the test filename to the name of the detection instead.
        # These are what we should write to the file
        for d in detection_tests:
            filename = os.path.basename(d)
            filename = filename.replace(".test.yml", ".yml")

            normalized_detection_names.append(d.replace(".test.yml", ".yml").replace("tests/", "detections/"))

        # Generate an appropriate config file for this test
        mock_settings = copy.deepcopy(config)
        # This may be able to support as many as 2 for GitHub Actions...
        # we will have to determine in testing.
        mock_settings.num_containers = 1

        # Must be selected since we are passing in a list of detections
        mock_settings.mode = DetectionTestingMode.selected
        # Pass in the list of detections to run
        mock_settings.detections_list = normalized_detection_names

        
        # We want to persist security content and run with the escu package that we created.
        #Note that if we haven't checked this out yet, we will check it out for you.
        #mock_settings['persist_security_content'] = True

        mock_settings.mock = False

        # Make sure that it still validates after all of the changes

        try:
            with open(fname, 'w') as outfile:
                yamlData = yaml.dump(mock_settings.__dict__)
                outfile.write(yaml.dump(yamlData))

        except Exception as e:
            print("Error writing config file %s: [%s]\n\tQuitting..." % (
                fname, str(e)), file=sys.stderr)
            return False

    return True




    


def main(config: TestConfig, director:DirectorOutputDto):
    #Disable insecure warnings.  We make a number of HTTPS requests to Splunk
    #docker containers that we've set up.  Without this line, we get an 
    #insecure warning every time due to invalid cert.
    requests.packages.urllib3.disable_warnings()


    #Get a handle to the git repo
    github_service = GithubService(config)

    #Get all of the detections that we will test in this run
    detections_to_test = github_service.get_detections_to_test(config, director)
    
    print("***This run will test [%d] detections!***"%(len(detections_to_test)))
    


    
    


    # If this is a mock run, finish it now
    if config.mock:
        #The function below 
        if finish_mock(config, detections_to_test):
            # mock was successful!
            print("Mock successful!  Manifests generated!")
            sys.exit(0)
        else:
            print("There was an unrecoverage error during the mock.\n\tQuitting...",file=sys.stderr)
            sys.exit(1)

    

    
    
    
    #This functionality shouldn't be in
    #detection_testing_execution.  We will move it elsewhere
    '''
    def shutdown_signal_handler_setup(sig, frame):
        
        print(f"Signal {sig} received... stopping all [{config.num_containers}] containers and shutting down...")
        shutdown_client = docker.client.from_env()
        errorCount = 0
        for container_number in range(config.num_containers):
            container_name = config.container_name%container_number
            print(f"Shutting down {container_name}...", file=sys.stderr, end='')
            sys.stdout.flush()
            try:
                container = shutdown_client.containers.get(container_name)
                #Note that stopping does not remove any of the volumes or logs,
                #so stopping can be useful if we want to debug any container failure 
                container.stop(timeout=10)
                print("done", file=sys.stderr)
            except Exception as e:
                print(f"Error trying to shut down {container_name}. It may have already shut down.  Stop it youself with 'docker containter stop {container_name}", sys.stderr)
                errorCount += 1
        if errorCount == 0:
            print("All containers shut down successfully", file=sys.stderr)        
        else:
            print(f"{errorCount} containers may still be running. Find out what is running with:\n\t'docker container ls'\nand shut them down with\n\t'docker container stop CONTAINER_NAME' ", file=sys.stderr)
        
        print("Quitting...",file=sys.stderr)
        #We must use os._exit(1) because sys.exit(1) actually generates an exception which can be caught! And then we don't Quit!
        os._exit(1)
        

            

    #Setup requires a different teardown handler than during execution
    signal.signal(signal.SIGINT, shutdown_signal_handler_setup)
    '''


    try:
        cm = instance_manager.InstanceManager(config,
                                              detections_to_test)
    except Exception as e:
        print("Error - unrecoverable error trying to set up the containers: [%s].\n\tQuitting..."%(str(e)),file=sys.stderr)
        sys.exit(1)

    def shutdown_signal_handler_execution(sig, frame):
        #Set that a container has failed which will gracefully stop the other containers.
        #This way we get our full cleanup routine, too!
        print("Got a signal to shut down. Shutting down all containers, please wait...", file=sys.stderr)
        
        cm.checkFailures()
    
    #Update the signal handler

    signal.signal(signal.SIGINT, shutdown_signal_handler_execution)
    try:
        result = cm.run_test()
    except Exception as e:
        print("Error - there was an error running the tests: [%s]\n\tQuitting..."%(str(e)),file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


    cm.shared_test_objects.generate_results_file(pathlib.Path("summary.json"))

    #github_service.update_and_commit_passed_tests(cm.synchronization_object.successes)
    

    #Return code indicates whether testing succeeded and all tests were run.
    #It does NOT indicate that all tests passed!
    if result is True:
        print("Test Execution Successful")
        sys.exit(0)
    else:
        print("Test Execution Failed - review the logs for more details")
        #Because one or more of the threads could be stuck in a certain setup loop, like
        #trying to copy files to a containers (which igonores errors), we must os._exit
        #instead of sys.exit
        os._exit(1)




