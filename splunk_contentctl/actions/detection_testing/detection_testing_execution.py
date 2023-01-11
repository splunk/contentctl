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


CONTAINER_APP_DIRECTORY = "apps"
MOCK_DIRECTORY = "mock_directory"


def copy_local_apps_to_directory(config: TestConfig):

    if config.mock:
        shutil.rmtree(MOCK_DIRECTORY, ignore_errors=True)

    try:
        # Make sure the directory exists.  If it already did, that's okay. Don't delete anything from it
        # We want to re-use previously downloaded apps
        os.makedirs(CONTAINER_APP_DIRECTORY, exist_ok=True)

    except Exception as e:
        raise (
            Exception(
                f"Some error occured when trying to make the {CONTAINER_APP_DIRECTORY}: [{str(e)}]"
            )
        )

    for app in config.apps:

        if app.must_download_from_splunkbase == False:

            if app.local_path is not None:

                if app.local_path == os.path.join(
                    CONTAINER_APP_DIRECTORY, pathlib.Path(app.local_path).name
                ):
                    print(f"same file {app.local_path}, skip...")
                else:
                    shutil.copy(
                        app.local_path,
                        os.path.join(
                            CONTAINER_APP_DIRECTORY, pathlib.Path(app.local_path).name
                        ),
                    )
            elif app.http_path:
                filename = pathlib.Path(
                    urlparse(app.http_path).path
                ).name  # get the filename from the url
                download_path = os.path.join(CONTAINER_APP_DIRECTORY, filename)
                Utils.download_file_from_http(
                    app.http_path, download_path, verbose_print=True
                )
                app.local_path = download_path
            else:
                raise (
                    Exception(
                        f"Could not download {app.title}, not http_path or local_path or Splunkbase Credentials provided"
                    )
                )

        else:
            # no need to do anything, the containers will download from splunkbase
            pass
    """
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
    """


def main(config: TestConfig, detections: list[Detection]):
    # Disable insecure warnings.  We make a number of HTTPS requests to Splunk
    # docker containers that we've set up.  Without this line, we get an
    # insecure warning every time due to invalid cert.
    requests.packages.urllib3.disable_warnings()

    print("***This run will test [%d] detections!***" % (len(detections)))

    try:
        copy_local_apps_to_directory(config)
    except Exception as e:
        print(f"Error download application(s): {str(e)}")
        sys.exit(1)

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
