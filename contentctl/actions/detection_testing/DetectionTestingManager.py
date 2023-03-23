from contentctl.objects.test_config import TestConfig
from contentctl.actions.detection_testing.infrastructures.DetectionTestingInfrastructure import (
    DetectionTestingInfrastructure,
)
from contentctl.actions.detection_testing.infrastructures.DetectionTestingInfrastructureContainer import (
    DetectionTestingInfrastructureContainer,
)
from contentctl.actions.detection_testing.infrastructures.DetectionTestingInfrastructureServer import (
    DetectionTestingInfrastructureServer,
)

from contentctl.objects.app import App
import pathlib
import os
from contentctl.helper.utils import Utils
from urllib.parse import urlparse
import time
from copy import deepcopy
from contentctl.objects.enums import DetectionTestingTargetInfrastructure
import signal
import datetime

# from queue import Queue

CONTAINER_APP_PATH = pathlib.Path("apps")

from dataclasses import dataclass

# import threading
import ctypes
from contentctl.actions.detection_testing.infrastructures.DetectionTestingInfrastructure import (
    DetectionTestingInfrastructure,
    DetectionTestingManagerOutputDto,
)
from contentctl.actions.detection_testing.views.DetectionTestingView import (
    DetectionTestingView,
)

from contentctl.objects.enums import PostTestBehavior

from pydantic import BaseModel, Field
from contentctl.input.director import DirectorOutputDto
from contentctl.objects.detection import Detection


import concurrent.futures

import tqdm


@dataclass(frozen=False)
class DetectionTestingManagerInputDto:
    config: TestConfig
    testContent: DirectorOutputDto
    views: list[DetectionTestingView]


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
        self.output_dto.inputQueue = self.input_dto.testContent.detections
        self.create_DetectionTestingInfrastructureObjects()

    def execute(self) -> DetectionTestingManagerOutputDto:
        def sigint_handler(signum, frame):
            print("SIGINT (Ctrl-C Received.  Shutting down test...)")
            self.output_dto.terminate = True
            if self.input_dto.config.post_test_behavior in [
                PostTestBehavior.always_pause,
                PostTestBehavior.pause_on_failure,
            ]:
                # It is possible that we are stuck waiting at in input() prompt, so inject
                # a newline '\r\n' which will cause that wait to stop
                print("*******************************")
                print(
                    "If testing is paused and you are debugging a detection, you MUST hit CTRL-D at the prompt to complete shutdown."
                )
                print("*******************************")

        signal.signal(signal.SIGINT, sigint_handler)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.input_dto.config.num_containers,
        ) as instance_pool, concurrent.futures.ThreadPoolExecutor(
            max_workers=len(self.input_dto.views)
        ) as view_runner, concurrent.futures.ThreadPoolExecutor(
            max_workers=self.input_dto.config.num_containers,
        ) as view_shutdowner:

            # Start all the views
            future_views = {
                view_runner.submit(view.setup): view for view in self.input_dto.views
            }
            # Configure all the instances
            future_instances_setup = {
                instance_pool.submit(instance.setup): instance
                for instance in self.detectionTestingInfrastructureObjects
            }

            # Wait for all instances to be set up
            for future in concurrent.futures.as_completed(future_instances_setup):
                try:
                    result = future.result()
                except Exception as e:
                    self.output_dto.terminate = True
                    print(f"Error setting up container: {str(e)}")

            # Start and wait for all tests to run
            if not self.output_dto.terminate:
                self.output_dto.start_time = datetime.datetime.now()
                future_instances_execute = {
                    instance_pool.submit(instance.execute): instance
                    for instance in self.detectionTestingInfrastructureObjects
                }
                # What for execution to finish
                for future in concurrent.futures.as_completed(future_instances_execute):
                    try:
                        result = future.result()
                    except Exception as e:
                        self.output_dto.terminate = True
                        print(f"Error running in container: {str(e)}")

            self.output_dto.terminate = True

            future_views_shutdowner = {
                view_shutdowner.submit(view.stop): view for view in self.input_dto.views
            }
            for future in concurrent.futures.as_completed(future_views_shutdowner):
                try:
                    result = future.result()
                except Exception as e:
                    print(f"Error stopping view: {str(e)}")

            for future in concurrent.futures.as_completed(future_views):
                try:
                    result = future.result()
                except Exception as e:
                    print(f"Error running container: {str(e)}")

        return self.output_dto

    def create_DetectionTestingInfrastructureObjects(self):
        import sys

        for index in range(self.input_dto.config.num_containers):
            instanceConfig = deepcopy(self.input_dto.config)
            instanceConfig.api_port += index * 2
            instanceConfig.hec_port += index * 2
            instanceConfig.web_ui_port += index

            instanceConfig.container_name = instanceConfig.container_name % (index,)

            if (
                self.input_dto.config.target_infrastructure
                == DetectionTestingTargetInfrastructure.container
            ):

                self.detectionTestingInfrastructureObjects.append(
                    DetectionTestingInfrastructureContainer(
                        config=instanceConfig, sync_obj=self.output_dto
                    )
                )

            elif (
                self.input_dto.config.target_infrastructure
                == DetectionTestingTargetInfrastructure.server
            ):

                self.detectionTestingInfrastructureObjects.append(
                    DetectionTestingInfrastructureServer(
                        config=instanceConfig, sync_obj=self.output_dto
                    )
                )

            else:

                print(
                    f"Unsupported target infrastructure '{self.input_dto.config.target_infrastructure}'"
                )
                sys.exit(1)
