from splunk_contentctl.objects.test_config import TestConfig
from splunk_contentctl.objects.app import App
import pathlib
import os
from splunk_contentctl.helper.utils import Utils
from urllib.parse import urlparse
import time

# from queue import Queue

CONTAINER_APP_PATH = pathlib.Path("apps")

from dataclasses import dataclass

# import threading
import ctypes
from splunk_contentctl.actions.detection_testing.newModules.DetectionTestingInfrastructure import (
    DetectionTestingInfrastructure,
)
from splunk_contentctl.actions.detection_testing.newModules.DetectionTestingViewController import (
    DetectionTestingViewController,
)
from splunk_contentctl.actions.detection_testing.newModules.DetectionTestingViewWeb import (
    DetectionTestingViewWeb,
)

from splunk_contentctl.actions.detection_testing.newModules.DetectionTestingViewCLI import (
    DetectionTestingViewCLI,
)
from pydantic import BaseModel
from splunk_contentctl.input.director import DirectorOutputDto
from splunk_contentctl.objects.detection import Detection


def stubRun():
    print("running container")
    import time

    time.sleep(120)


@dataclass(frozen=True)
class DetectionTestingManagerInputDto:
    detectionTestingInfrastructureObjects: list[DetectionTestingInfrastructure]
    views: list[DetectionTestingViewController]
    config: TestConfig
    testContent: DirectorOutputDto
    # inputQueue: Queue[Detection] = Queue()
    tick_seconds: float = 1


@dataclass
class DetectionTestingManagerOutputDto:
    pass


class DetectionTestingManager(BaseModel):
    input_dto: DetectionTestingManagerInputDto
    output_dto: DetectionTestingManagerOutputDto = DetectionTestingManagerOutputDto()
    # pending_queue: Queue[Detection] = Queue()
    completed_queue: list = []

    # def __init__(self, output_dto: DetectionTestingManagerOutputDto):
    #    self.output_dto = output_dto

    def setup(self):
        # Some views, such as the Web View, will require some initial setup.
        for view in self.input_dto.views:
            view.setup()

        self.stage_apps()
        # for content in self.input_dto.testContent.detections:
        #    self.pending_queue.put(content)

        self.create_DetectionTestingInfrastructureObjects()

    def execute(
        self,
        detectionTestingManagerInputDto: DetectionTestingManagerInputDto,
    ) -> DetectionTestingManagerOutputDto:
        self.input_dto = detectionTestingManagerInputDto

        # Start all of the threads
        # for obj in self.input_dto.detectionTestingInfrastructureObjects:
        #    t = threading.Thread(obj.thread.run())

        i = DetectionTestingInfrastructure(config=self.input_dto.config)
        i.configure_imported_roles()
        i.configure_delete_indexes()
        i.configure_conf_file_datamodels()

        start_time = time.time()
        try:
            while True:
                print("status tick")
                elapsed_time = time.time() - start_time
                self.status(elapsed_time)
                time.sleep(self.input_dto.tick_seconds)
        except Exception as e:
            print("ERROR EXECUTING TEST")

        return DetectionTestingManagerOutputDto()

    def status(
        self,
        elapsed_time: float,
    ):
        for view in self.input_dto.views:
            view.showStatus(elapsed_time)

    def create_DetectionTestingInfrastructureObjects(self):

        pass

    def get_app_from_splunkbase(self, app: App, target_directory: pathlib.Path):
        print(f"App {app.title} will be downloaded by the container at runtime")

    def get_app_from_local_path(self, app: App, target_directory: pathlib.Path):
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

    def get_app_from_http_path(self, app: App, target_directory: pathlib.Path):
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

    def get_app(self, app: App, target_directory: pathlib.Path):
        if app.must_download_from_splunkbase:
            # This app will be downloaded by the container
            self.get_app_from_splunkbase(app, target_directory)
        elif app.local_path is not None:
            self.get_app_from_local_path(app, target_directory)
        elif app.http_path:
            self.get_app_from_http_path(app, target_directory)
        else:
            raise (
                Exception(
                    f"Error: Unable to get app {app.title} - no Splunkbase info, local_path, or http_path"
                )
            )

    def stage_apps(self):
        print("Preparing apps...")
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

        alphabetically_sorted_apps = sorted(
            self.input_dto.config.apps, key=lambda a: a.title
        )

        # Get all the other apps
        app_exceptions: list[str] = []
        for app in alphabetically_sorted_apps:
            try:
                self.get_app(app, CONTAINER_APP_PATH)
            except Exception as e:
                app_exceptions.append(
                    f"Error: Unable to stage app for installation: [{str(e)}"
                )
        if len(app_exceptions) == 0:
            print(
                f"[{len(self.input_dto.config.apps)}] apps processed successfully for installation"
            )
            return
        else:
            exceptions_string = "\n\t - ".join(app_exceptions)
            raise (
                Exception(
                    f"Error: Unable to stage {len(app_exceptions)} apps for installation:\n\t - {exceptions_string}"
                )
            )
