from pydantic import BaseModel
import abc
from typing import Callable
from splunk_contentctl.objects.test_config import TestConfig
from splunk_contentctl.actions.detection_testing.infrastructures.DetectionTestingInfrastructure import (
    DetectionTestingManagerOutputDto,
)

from splunk_contentctl.actions.detection_testing.views.DetectionTestingView import (
    DetectionTestingView,
)
import pathlib
import yaml

OUTPUT_FOLDER = "test_results"


class DetectionTestingViewFile(DetectionTestingView):
    def setup(self):
        pass

    def stop(self, summary_file_name: str = "summary.yml"):
        folder = pathlib.Path(self.config.repo_path) / OUTPUT_FOLDER
        output_file = folder / "summary.yml"

        folder.mkdir(parents=True, exist_ok=True)

        result_dict = self.getSummaryObject()

        # use the yaml writer class
        with open(output_file, "w") as res:
            res.write(yaml.dump(result_dict))

    def showStatus(self, interval: int = 60):
        pass

    def showResults(self):
        pass

    def createReport(self):
        pass
