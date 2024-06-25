from typing import List,Union
from contentctl.objects.config import test, test_servers, Container,Infrastructure
from contentctl.actions.detection_testing.infrastructures.DetectionTestingInfrastructure import DetectionTestingInfrastructure
from contentctl.actions.detection_testing.infrastructures.DetectionTestingInfrastructureContainer import DetectionTestingInfrastructureContainer
from contentctl.actions.detection_testing.infrastructures.DetectionTestingInfrastructureServer import DetectionTestingInfrastructureServer
from urllib.parse import urlparse
from copy import deepcopy
from contentctl.objects.enums import DetectionTestingTargetInfrastructure
import signal
import datetime
# from queue import Queue
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
from contentctl.objects.detection import Detection
import concurrent.futures
import docker


@dataclass(frozen=False)
class DetectionTestingManagerInputDto:
    config: Union[test,test_servers]
    detections: List[Detection]
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
        self.output_dto.inputQueue = self.input_dto.detections
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
            max_workers=len(self.input_dto.config.test_instances),
        ) as instance_pool, concurrent.futures.ThreadPoolExecutor(
            max_workers=len(self.input_dto.views)
        ) as view_runner, concurrent.futures.ThreadPoolExecutor(
            max_workers=len(self.input_dto.config.test_instances),
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
                # Wait for execution to finish
                for future in concurrent.futures.as_completed(future_instances_execute):
                    try:
                        result = future.result()
                    except Exception as e:
                        self.output_dto.terminate = True
                        print(f"Error running in container: {str(e)}")

            self.output_dto.terminate = True

            # Shut down all the views and wait for the shutdown to finish
            future_views_shutdowner = {
                view_shutdowner.submit(view.stop): view for view in self.input_dto.views
            }
            for future in concurrent.futures.as_completed(future_views_shutdowner):
                try:
                    result = future.result()
                except Exception as e:
                    print(f"Error stopping view: {str(e)}")

            # Wait for original view-related threads to complete
            for future in concurrent.futures.as_completed(future_views):
                try:
                    result = future.result()
                except Exception as e:
                    print(f"Error running container: {str(e)}")

        return self.output_dto

    def create_DetectionTestingInfrastructureObjects(self):
        #Make sure that, if we need to, we pull the appropriate container
        for infrastructure in self.input_dto.config.test_instances:
            if (isinstance(self.input_dto.config, test) and isinstance(infrastructure, Container)):
                try:
                    client = docker.from_env()
                except Exception as e:
                    raise Exception("Unable to connect to docker.  Are you sure that docker is running on this host?")
                try:
                    
                    parts = self.input_dto.config.container_settings.full_image_path.split(':')
                    if len(parts) != 2:
                        raise Exception(f"Expected to find a name:tag in {self.input_dto.config.container_settings.full_image_path}, "
                                        f"but instead found {parts}. Note that this path MUST include the tag, which is separated by ':'")
                    
                    print(
                        f"Getting the latest version of the container image [{self.input_dto.config.container_settings.full_image_path}]...",
                        end="",
                        flush=True,
                    )
                    client.images.pull(parts[0], tag=parts[1], platform="linux/amd64")
                    print("done!")
                    break
                except Exception as e:
                    raise Exception(f"Failed to pull docker container image [{self.input_dto.config.container_settings.full_image_path}]: {str(e)}")

        already_staged_container_files = False
        for infrastructure in self.input_dto.config.test_instances:

            if (isinstance(self.input_dto.config, test) and isinstance(infrastructure, Container)):
                # Stage the files in the apps dir so that they can be passed directly to
                # subsequent containers. Do this here, instead of inside each container, to
                # avoid duplicate downloads/moves/copies
                if not already_staged_container_files:
                    self.input_dto.config.getContainerEnvironmentString(stage_file=True)
                    already_staged_container_files = True

                self.detectionTestingInfrastructureObjects.append(
                    DetectionTestingInfrastructureContainer(
                        global_config=self.input_dto.config, infrastructure=infrastructure, sync_obj=self.output_dto
                    )
                )

            elif (isinstance(self.input_dto.config, test_servers) and isinstance(infrastructure, Infrastructure)):
                self.detectionTestingInfrastructureObjects.append(
                    DetectionTestingInfrastructureServer(
                        global_config=self.input_dto.config, infrastructure=infrastructure, sync_obj=self.output_dto
                    )
                )

            else:

                raise Exception(f"Unsupported target infrastructure '{infrastructure}' and config type {self.input_dto.config}")
                
