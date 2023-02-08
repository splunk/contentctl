from splunk_contentctl.objects.test_config import TestConfig
from splunk_contentctl.actions.detection_testing.newModules.DetectionTestingInfrastructure import (
    DetectionTestingInfrastructure,
)
from splunk_contentctl.objects.app import App
import pathlib
import os
from splunk_contentctl.helper.utils import Utils
from urllib.parse import urlparse
import time
from copy import deepcopy

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
    config: TestConfig
    testContent: DirectorOutputDto
    views: list[DetectionTestingViewController] = [
        DetectionTestingViewWeb(),
        DetectionTestingViewCLI(),
    ]
    tick_seconds: float = 1


@dataclass
class DetectionTestingManagerOutputDto:
    outputQueue: list[Detection] = []


class DetectionTestingManager(BaseModel):
    input_dto: DetectionTestingManagerInputDto
    output_dto: DetectionTestingManagerOutputDto
    detectionTestingInfrastructureObjects: list[DetectionTestingInfrastructure] = []

    def setup(self):
        # Some views, such as the Web View, will require some initial setup.
        for view in self.input_dto.views:
            view.setup()

        # for content in self.input_dto.testContent.detections:
        #    self.pending_queue.put(content)

        self.create_DetectionTestingInfrastructureObjects()

    def execute(self) -> DetectionTestingManagerOutputDto:

        # Start all of the threads
        # for obj in self.input_dto.detectionTestingInfrastructureObjects:
        #    t = threading.Thread(obj.thread.run())

        for obj in self.detectionTestingInfrastructureObjects:
            obj.setup()

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
        for instance_index in range(self.input_dto.config.num_containers):
            instanceConfig = deepcopy(self.input_dto.config)
            instanceConfig.api_port += instance_index
            instanceConfig.web_ui_port += instance_index
            instanceConfig.hec_port += instance_index
            instanceConfig.container_name = instanceConfig.container_name.format(
                instance_index
            )
            self.detectionTestingInfrastructureObjects.append(
                DetectionTestingInfrastructure(config=instanceConfig)
            )
