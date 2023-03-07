from pydantic import BaseModel
import abc
from typing import Callable
from splunk_contentctl.objects.test_config import TestConfig
from splunk_contentctl.actions.detection_testing.DetectionTestingInfrastructure import (
    DetectionTestingManagerOutputDto,
)

from splunk_contentctl.actions.detection_testing.DetectionTestingView import (
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

        total_untested = len(self.sync_obj.inputQueue)

        tested_detections = []
        total_pass = 0
        total_fail = 0
        for detection in self.sync_obj.outputQueue:
            summary = detection.get_summary()
            if summary["success"] == True:
                total_pass += 1
            else:
                total_fail += 1
            tested_detections.append(summary)
        # All failures appear first
        tested_detections.sort(key=lambda x: (x["success"], x["name"]))

        untested_detections = []
        for detection in self.sync_obj.inputQueue:
            untested_detections.append(detection.get_summary())
        # All failures appear first
        untested_detections.sort(key=lambda x: x["name"])

        if (total_fail + len(untested_detections)) == 0:
            overall_success = True
        else:
            overall_success = False
        result_dict = {
            "summary": {
                "success": overall_success,
                "total_pass": total_pass,
                "total_fail_or_untested": total_fail + total_untested,
                "success_rate": total_pass / (total_pass + total_fail + total_untested),
            },
            "tested_detections": tested_detections,
            "untested_detections": untested_detections,
        }

        # use the yaml writer class
        with open(output_file, "w") as res:
            res.write(yaml.dump(result_dict))

    def showStatus(self, interval: int = 60):
        pass

    def showResults(self):
        pass

    def createReport(self):
        pass
