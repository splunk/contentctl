import abc
import datetime
from typing import Any

from pydantic import BaseModel

from contentctl.objects.config import test_common

from contentctl.actions.detection_testing.infrastructures.DetectionTestingInfrastructure import (
    DetectionTestingManagerOutputDto,
)
from contentctl.helper.utils import Utils
from contentctl.objects.enums import DetectionStatus
from contentctl.objects.base_test_result import TestResultStatus


class DetectionTestingView(BaseModel, abc.ABC):
    config: test_common
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
        if self.sync_obj.start_time is None:
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
        except Exception:
            raise Exception("Unknown ETA")
        return remaining_time

    def getSummaryObject(
        self,
        test_result_fields: list[str] = ["success", "message", "exception", "status", "duration", "wait_duration"],
        test_job_fields: list[str] = ["resultCount", "runDuration"],
    ) -> dict[str, dict[str, Any] | list[dict[str, Any]] | str]:
        """
        Iterates over detections, consolidating results into a single dict and aggregating metrics
        :param test_result_fields: fields to pull from the test result
        :param test_job_fields: fields to pull from the job content of the test result
        :returns: summary dict
        """
        # Init the list of tested and skipped detections, and some metrics aggregate counters
        tested_detections: list[dict[str, Any]] = []
        skipped_detections: list[dict[str, Any]] = []
        total_pass = 0
        total_fail = 0
        total_skipped = 0
        total_production = 0
        total_experimental = 0
        total_deprecated = 0
        total_manual = 0

        # Iterate the detections tested (anything in the output queue was tested)
        for detection in self.sync_obj.outputQueue:
            # Get a summary dict of the testing of the detection
            summary = detection.get_summary(
                test_job_fields=test_job_fields, test_result_fields=test_result_fields
            )

            # Aggregate detection pass/fail metrics
            if detection.test_status == TestResultStatus.FAIL:
                total_fail += 1
            elif detection.test_status == TestResultStatus.PASS:
                total_pass += 1
            elif detection.test_status == TestResultStatus.SKIP:
                total_skipped += 1

            # Aggregate production status metrics
            if detection.status == DetectionStatus.production.value:                                # type: ignore
                total_production += 1
            elif detection.status == DetectionStatus.experimental.value:                            # type: ignore
                total_experimental += 1
            elif detection.status == DetectionStatus.deprecated.value:                              # type: ignore
                total_deprecated += 1

            # Check if the detection is manual_test
            if detection.tags.manual_test is not None:
                total_manual += 1

            # Append to our list (skipped or tested)
            if detection.test_status == TestResultStatus.SKIP:
                skipped_detections.append(summary)
            else:
                tested_detections.append(summary)

        # Sort tested detections s.t. all failures appear first, then by name
        tested_detections.sort(
            key=lambda x: (
                x["success"],
                x["name"]
            )
        )

        # Sort skipped detections s.t. detections w/ tests appear before those w/o, then by name
        skipped_detections.sort(
            key=lambda x: (
                0 if len(x["tests"]) > 0 else 1,
                x["name"]
            )
        )

        # TODO (#267): Align test reporting more closely w/ status enums (as it relates to
        #   "untested")
        # Aggregate summaries for the untested detections (anything still in the input queue was untested)
        total_untested = len(self.sync_obj.inputQueue)
        untested_detections: list[dict[str, Any]] = []
        for detection in self.sync_obj.inputQueue:
            untested_detections.append(detection.get_summary())

        # Sort by detection name
        untested_detections.sort(key=lambda x: x["name"])

        # If any detection failed, or if there are untested detections, the overall success is False
        if (total_fail + len(untested_detections)) == 0:
            overall_success = True
        else:
            overall_success = False

        # Compute total detections
        total_detections = total_fail + total_pass + total_untested + total_skipped

        # Compute total detections actually tested (at least one test not skipped)
        total_tested_detections = total_fail + total_pass

        # Compute the percentage of completion for testing, as well as the success rate
        percent_complete = Utils.getPercent(
            len(tested_detections), len(untested_detections), 1
        )
        success_rate = Utils.getPercent(
            total_pass, total_tested_detections, 1
        )

        # TODO (#230): expand testing metrics reported (and make nested)
        # Construct and return the larger results dict
        result_dict = {
            "summary": {
                "mode": self.config.getModeName(),
                "enable_integration_testing": self.config.enable_integration_testing,
                "success": overall_success,
                "total_detections": total_detections,
                "total_tested_detections": total_tested_detections,
                "total_pass": total_pass,
                "total_fail": total_fail,
                "total_skipped": total_skipped,
                "total_untested": total_untested,
                "total_production": total_production,
                "total_experimental": total_experimental,
                "total_deprecated": total_deprecated,
                "total_manual": total_manual,
                "success_rate": success_rate,
            },
            "tested_detections": tested_detections,
            "skipped_detections": skipped_detections,
            "untested_detections": untested_detections,
            "percent_complete": percent_complete,
        }
        return result_dict
