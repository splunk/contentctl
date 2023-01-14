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


from splunk_contentctl.actions.detection_testing.modules.instance_manager import (
    InstanceManager,
)
from splunk_contentctl.objects.detection import Detection
from splunk_contentctl.helper.utils import Utils
from splunk_contentctl.objects.test_config import TestConfig
from splunk_contentctl.actions.detection_testing.modules.github_service import (
    GithubService,
)
from splunk_contentctl.objects.enums import DetectionTestingMode
from splunk_contentctl.actions.generate import DirectorOutputDto
import yaml
from splunk_contentctl.objects.app import App

CONTAINER_APP_PATH = pathlib.Path("apps")





def main(config: TestConfig, testDirector: DirectorOutputDto]):
    # Disable insecure warnings.  We make a number of HTTP requests to Splunk
    # docker containers that we've set up.  Without this line, we get an
    # insecure warning every time due to invalid cert.

    requests.packages.urllib3.disable_warnings()
    detections = testDirector.detections
    try:
        stage_apps(config)
    except Exception as e:
        raise (Exception(f"Error downloading application(s): {str(e)}"))

    try:
        cm = InstanceManager(config, detections)

    except Exception as e:
        print(
            "Error - unrecoverable error trying to set up the containers: [%s].\n\tQuitting..."
            % (str(e)),
            file=sys.stderr,
        )
        sys.exit(1)

    def shutdown_signal_handler_execution(sig, frame):
        # Set that a container has failed which will gracefully stop the other containers.
        # This way we get our full cleanup routine, too!
        print(
            "[CONTROLLER]: Received SIGINT (CTRL-C). Shutting down and finalizing results. Please note this may take 2-3 minutes."
        )
        cm.force_finish()

    # Update the signal handler

    signal.signal(signal.SIGINT, shutdown_signal_handler_execution)

    try:
        result = cm.run_test()
    except Exception as e:
        print(
            "Error - there was an error running the tests: [%s]\n\tQuitting..."
            % (str(e)),
            file=sys.stderr,
        )
        import traceback

        traceback.print_exc()
        sys.exit(1)

    cm.shared_test_objects.generate_results_file(pathlib.Path("summary.json"))

    # github_service.update_and_commit_passed_tests(cm.synchronization_object.successes)

    # Return code indicates whether testing succeeded and all tests were run.
    # It does NOT indicate that all tests passed!
    if result is True:
        print("Test Execution Successful")
        sys.exit(0)
    else:
        print("Test Execution Failed - review the logs for more details")
        # Because one or more of the threads could be stuck in a certain setup loop, like
        # trying to copy files to a containers (which igonores errors), we must os._exit
        # instead of sys.exit
        os._exit(1)
