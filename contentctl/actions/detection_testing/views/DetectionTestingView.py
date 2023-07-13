from pydantic import BaseModel
import abc
from typing import Callable
from contentctl.objects.test_config import TestConfig
import datetime
from contentctl.actions.detection_testing.infrastructures.DetectionTestingInfrastructure import (
    DetectionTestingManagerOutputDto,
)
from contentctl.helper.utils import Utils


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

    def getCurrent(self) -> list[str]:
        return [
            d
            for d in self.sync_obj.currentTestingQueue
            if self.sync_obj.currentTestingQueue[d] is not None
        ]

    def getRuntime(self) -> datetime.timedelta:
        if self.sync_obj.start_time == None:
            raise Exception("Unknown Time")
        runtime = datetime.datetime.now() - self.sync_obj.start_time
        runtime -= datetime.timedelta(microseconds=runtime.microseconds)
        return runtime

    def getETA(self) -> datetime.timedelta:
        summary = self.getSummaryObject()

        num_tested = len(summary.get("tested_detections", []))
        num_untested = len(summary.get("untested_detections", []))

        if num_tested == 0:
            raise Exception("Unknown ETA")
        elif num_untested == 0:
            raise Exception("Finishing test")

        try:
            runtime = self.getRuntime()
            time_per_detection = runtime / num_tested
            remaining_time = (num_untested+.5) * time_per_detection
            remaining_time -= datetime.timedelta(
                microseconds=remaining_time.microseconds
            )
        except:
            raise Exception("Unknown ETA")
        return remaining_time

    def getSummaryObject(
        self,
        test_model_fields: list[str] = ["success", "message"],
        test_job_fields: list[str] = ["resultCount", "runDuration"],
    ) -> dict:
        total_untested = len(self.sync_obj.inputQueue)

        tested_detections = []
        total_pass = 0
        total_fail = 0
        for detection in self.sync_obj.outputQueue:
            summary = detection.get_summary(
                test_job_fields=test_job_fields, test_model_fields=test_model_fields
            )
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

        percent_complete = Utils.getPercent(
            len(tested_detections), len(untested_detections), 1
        )
        success_rate = Utils.getPercent(
            total_pass, total_fail + total_pass + total_untested, 1
        )

        result_dict = {
            "summary": {
                "success": overall_success,
                "total_detections": total_pass + total_fail,
                "total_pass": total_pass,
                "total_fail_or_untested": total_fail + total_untested,
                "success_rate": success_rate,
            },
            "tested_detections": tested_detections,
            "untested_detections": untested_detections,
            "percent_complete": percent_complete,
        }
        return result_dict
