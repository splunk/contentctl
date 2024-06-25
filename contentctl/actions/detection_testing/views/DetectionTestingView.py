import abc
import datetime

from pydantic import BaseModel

from contentctl.objects.config import test_common

from contentctl.actions.detection_testing.infrastructures.DetectionTestingInfrastructure import (
    DetectionTestingManagerOutputDto,
)
from contentctl.helper.utils import Utils
from contentctl.objects.enums import DetectionStatus


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
    ) -> dict:
        """
        Iterates over detections, consolidating results into a single dict and aggregating metrics
        :param test_result_fields: fields to pull from the test result
        :param test_job_fields: fields to pull from the job content of the test result
        :returns: summary dict
        """
        # Init the list of tested detections, and some metrics aggregate counters
        tested_detections = []
        total_pass = 0
        total_fail = 0
        total_skipped = 0

        # Iterate the detections tested (anything in the output queue was tested)
        for detection in self.sync_obj.outputQueue:
            # Get a summary dict of the testing of the detection
            summary = detection.get_summary(
                test_job_fields=test_job_fields, test_result_fields=test_result_fields
            )

            # Aggregate detection pass/fail metrics
            if summary["success"] is False:
                total_fail += 1
            else:
                #Test is marked as a success, but we need to determine if there were skipped unit tests
                #SKIPPED tests still show a success in this field, but we want to count them differently
                pass_increment = 1
                for test in summary.get("tests"):
                    if test.get("test_type") == "unit" and test.get("status") == "skip":
                        total_skipped += 1
                        #Test should not count as a pass, so do not increment the count
                        pass_increment = 0
                        break
                total_pass += pass_increment
                

            # Append to our list
            tested_detections.append(summary)

        # Sort s.t. all failures appear first (then by name)
        #Second short condition is a hack to get detections with unit skipped tests to appear above pass tests
        tested_detections.sort(key=lambda x: (x["success"], 0 if x.get("tests",[{}])[0].get("status","status_missing")=="skip" else 1, x["name"]))

        # Aggregate summaries for the untested detections (anything still in the input queue was untested)
        total_untested = len(self.sync_obj.inputQueue)
        untested_detections = []
        for detection in self.sync_obj.inputQueue:
            untested_detections.append(detection.get_summary())

        # Sort by detection name
        untested_detections.sort(key=lambda x: x["name"])

        # Get lists of detections (name only) that were skipped due to their status (experimental or deprecated)
        experimental_detections = sorted([
            detection.name for detection in self.sync_obj.skippedQueue if detection.status == DetectionStatus.experimental.value
        ])
        deprecated_detections = sorted([
            detection.name for detection in self.sync_obj.skippedQueue if detection.status == DetectionStatus.deprecated.value
        ])

        # If any detection failed, the overall success is False
        if (total_fail + len(untested_detections)) == 0:
            overall_success = True
        else:
            overall_success = False

        # Compute total detections
        total_detections = total_fail + total_pass + total_untested + total_skipped


        # Compute the percentage of completion for testing, as well as the success rate
        percent_complete = Utils.getPercent(
            len(tested_detections), len(untested_detections), 1
        )
        success_rate = Utils.getPercent(
            total_pass, total_detections-total_skipped, 1
        )

        # TODO (cmcginley): add stats around total test cases and unit/integration test
        #   sucess/failure? maybe configurable reporting? add section to summary called
        #   "testwise_summary" listing per test metrics (e.g. total test, total tests passed, ...);
        #   also list num skipped at both detection and test level
        # Construct and return the larger results dict
        result_dict = {
            "summary": {
                "success": overall_success,
                "total_detections": total_detections,
                "total_pass": total_pass,
                "total_fail": total_fail,
                "total_skipped": total_skipped,
                "total_untested": total_untested,
                "total_experimental_or_deprecated": len(deprecated_detections+experimental_detections),
                "success_rate": success_rate,
            },
            "tested_detections": tested_detections,
            "untested_detections": untested_detections,
            "percent_complete": percent_complete,
            "deprecated_detections": deprecated_detections,
            "experimental_detections": experimental_detections

        }
        return result_dict
