from splunk_contentctl.objects.test_config import TestConfig
from splunk_contentctl.actions.detection_testing.newModules.DetectionTestingInfrastructure import (
    DetectionTestingInfrastructure,
    DetectionTestingContainer,
)
from splunk_contentctl.objects.app import App
import pathlib
import os
from splunk_contentctl.helper.utils import Utils
from urllib.parse import urlparse
import time
from copy import deepcopy
from splunk_contentctl.objects.enums import DetectionTestingTargetInfrastructure

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

from pydantic import BaseModel
from splunk_contentctl.input.director import DirectorOutputDto
from splunk_contentctl.objects.detection import Detection


def stubRun():
    print("running container")
    import time

    time.sleep(120)


@dataclass(frozen=False)
class DetectionTestingManagerInputDto:
    config: TestConfig
    testContent: DirectorOutputDto
    views: list[DetectionTestingViewController]
    tick_seconds: float = 1


@dataclass
class DetectionTestingManagerOutputDto:
    outputQueue: list[Detection]


class DetectionTestingManager(BaseModel):
    input_dto: DetectionTestingManagerInputDto
    output_dto: DetectionTestingManagerOutputDto
    detectionTestingInfrastructureObjects: list[DetectionTestingInfrastructure] = []

    def setup(self):
        # Some views, such as the Web View, will require some initial setup.
        # for view in self.input_dto.views:
        #    view.setup()

        # for content in self.input_dto.testContent.detections:
        #    self.pending_queue.put(content)

        self.input_dto.config.num_containers = 2
        self.create_DetectionTestingInfrastructureObjects()

    def execute(self) -> DetectionTestingManagerOutputDto:

        # Start all of the threads
        # for obj in self.input_dto.detectionTestingInfrastructureObjects:
        #    t = threading.Thread(obj.thread.run())
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.input_dto.config.num_containers,
        ) as instance_runner, concurrent.futures.ThreadPoolExecutor(
            max_workers=len(self.input_dto.views)
        ) as view_runner:
            future_views = {
                view_runner.submit(view.setup): view for view in self.input_dto.views
            }
            print("Views started, starting containers")
            future_instances = {
                instance_runner.submit(instance.setup): instance
                for instance in self.detectionTestingInfrastructureObjects
            }
            print("containers started")
            for future in concurrent.futures.as_completed(future_instances):
                print(f"Finished running instance {future}")
                try:
                    result = future.result()
                except Exception as e:
                    print(f"Error running container: {str(e)}")
            print("containers exited")
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.input_dto.config.num_containers,
            ) as view_shutdowner:
                print("starting view stopper")
                future_views_shutdowner = {
                    view_shutdowner.submit(view.stop): view
                    for view in self.input_dto.views
                }
                for future in concurrent.futures.as_completed(future_views_shutdowner):
                    print(f"Finished stopping view {future}")
                    try:
                        result = future.result()
                    except Exception as e:
                        print(f"Error stopping view: {str(e)}")
                print("view stoppers stopped")

            for future in concurrent.futures.as_completed(future_views):
                print(f"Finished running view {future}")
                try:
                    result = future.result()
                except Exception as e:
                    print(f"Error running container: {str(e)}")
            print("all views futures stopped")

        """
        for obj in self.detectionTestingInfrastructureObjects:
            import threading

            t = threading.Thread(target=obj.setup, daemon=True)
            t.start()

        start_time = time.time()
        try:
            while True:
                print("status tick")
                elapsed_time = time.time() - start_time
                self.status(elapsed_time)
                time.sleep(self.input_dto.tick_seconds)
        except Exception as e:
            print("ERROR EXECUTING TEST")
        """
        print("do we get here?")
        import sys

        sys.exit(0)
        return DetectionTestingManagerOutputDto()

    def status(
        self,
        elapsed_time: float,
    ):
        for view in self.input_dto.views:
            view.showStatus(elapsed_time)

    def create_DetectionTestingInfrastructureObjects(self):
        import sys

        for index in range(self.input_dto.config.num_containers):
            instanceConfig = deepcopy(self.input_dto.config)
            instanceConfig.api_port += index * 2
            instanceConfig.hec_port += index * 2
            instanceConfig.web_ui_port += index + 1

            instanceConfig.container_name = instanceConfig.container_name % (index,)

            if (
                self.input_dto.config.target_infrastructure
                == DetectionTestingTargetInfrastructure.container
            ):

                self.detectionTestingInfrastructureObjects.append(
                    DetectionTestingContainer(config=instanceConfig)
                )

            elif (
                self.input_dto.config.target_infrastructure
                == DetectionTestingTargetInfrastructure.server
            ):

                print("server support not yet implemented")
                sys.exit(1)
            else:

                print(
                    f"Unsupported target infrastructure '{self.input_dto.config.target_infrastructure}'"
                )
                sys.exit(1)
