from pydantic import BaseModel
import abc
from typing import Callable
from splunk_contentctl.objects.test_config import TestConfig
from splunk_contentctl.actions.detection_testing.DetectionTestingInfrastructure import (
    DetectionTestingManagerOutputDto,
)


class DetectionTestingView(BaseModel, abc.ABC):
    config: TestConfig
    sync_obj: DetectionTestingManagerOutputDto

    interval: float = 10
    next_update: float = 0

    def setup(self):
        pass

    def stop(self):
        pass

    def showStatus(self, interval: int = 60):
        pass

    def showResults(self):
        pass

    def createReport(self):
        pass
