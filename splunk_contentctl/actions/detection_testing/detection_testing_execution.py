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


def get_app_from_splunkbase(app: App, target_directory: pathlib.Path):
    print(f"App {app.title} will be downloaded by the container at runtime")
    pass


def get_app_from_local_path(app: App, target_directory: pathlib.Path):
    if app.local_path is None:
        raise (
            Exception(
                f"Error: cannot copy app {app.title} from local.  local_path is None"
            )
        )

    path_to_local_file = pathlib.Path(app.local_path)
    path_to_destination = target_directory.joinpath(path_to_local_file.name)
    Utils.copy_local_file(
        str(path_to_local_file), str(path_to_destination), verbose_print=True
    )


def get_app_from_http_path(app: App, target_directory: pathlib.Path):
    if app.http_path is None:
        raise (
            Exception(
                f"Error: cannot download app {app.title} from http.  http_path is None"
            )
        )
    # print(f"Downloading http app [{app.title} - {app.release}]...", end="")
    path_on_server = str(urlparse(app.http_path).path)
    # Get just the filename from that path
    filename = pathlib.Path(path_on_server).name
    destination_path = target_directory.joinpath(filename)
    Utils.download_file_from_http(
        app.http_path, destination_path.as_posix(), verbose_print=True
    )


def get_app(app: App, target_directory: pathlib.Path):
    if app.must_download_from_splunkbase:
        # This app will be downloaded by the container
        get_app_from_splunkbase(app, target_directory)
    elif app.local_path is not None:
        get_app_from_local_path(app, target_directory)
    elif app.http_path:
        get_app_from_http_path(app, target_directory)
    else:
        raise (
            Exception(
                f"Error: Unable to get app {app.title} - no Splunkbase info, local_path, or http_path"
            )
        )


def stage_apps(config: TestConfig):

    try:
        # Make sure the directory exists.  If it already did, that's okay. Don't delete anything from it
        # We want to re-use previously downloaded apps
        os.makedirs(CONTAINER_APP_PATH, exist_ok=True)

    except Exception as e:
        raise (
            Exception(
                f"Error: When trying to make the {CONTAINER_APP_PATH}: [{str(e)}]"
            )
        )

    alphabetically_sorted_apps = sorted(config.apps, key=lambda a: a.title)

    # Get all the splunkbase apps
    for app in [
        a for a in alphabetically_sorted_apps if a.must_download_from_splunkbase
    ]:
        get_app_from_splunkbase(app, CONTAINER_APP_PATH)

    # Get all the other apps
    app_exceptions: list[str] = []
    for app in alphabetically_sorted_apps:
        try:
            get_app(app, CONTAINER_APP_PATH)
        except Exception as e:
            app_exceptions.append(
                f"Error: Unable to stage app for installation: [{str(e)}"
            )
    if len(app_exceptions) == 0:
        print(f"[{len(config.apps)}] apps processed successfully for installation")
        return
    else:
        exceptions_string = "\n\t - ".join(app_exceptions)
        raise (
            Exception(
                f"Error: Unable to stage {len(app_exceptions)} apps for installation:\n\t - {exceptions_string}"
            )
        )


def main(config: TestConfig, detections: list[Detection]):
    # Disable insecure warnings.  We make a number of HTTPS requests to Splunk
    # docker containers that we've set up.  Without this line, we get an
    # insecure warning every time due to invalid cert.
    requests.packages.urllib3.disable_warnings()

    try:
        stage_apps(config)
    except Exception as e:
        print(f"Error downloading application(s): {str(e)}")
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
