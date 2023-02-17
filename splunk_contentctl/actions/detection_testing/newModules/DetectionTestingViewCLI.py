from splunk_contentctl.actions.detection_testing.newModules.DetectionTestingView import (
    DetectionTestingView,
)

import time


class DetectionTestingViewCLI(DetectionTestingView):
    def setup(self):
        self.showStatus()

    def showStatus(self, interval: int = 60):
        while True:
            for i in range(interval):
                if self.sync_obj.terminate:
                    print("Detection Testing Completed")
                    return
                time.sleep(1)

            len_input = len(self.sync_obj.inputQueue)
            len_output = len(self.sync_obj.outputQueue)
            len_current = len(
                [
                    d
                    for d in self.sync_obj.currentTestingQueue
                    if self.sync_obj.currentTestingQueue[d] is not None
                ]
            )
            total_num_detections = len_input + len_output + len_current
            import datetime

            elapsed_timedelta = datetime.datetime.now() - self.sync_obj.start_time

            if len_output == 0:
                remaining_time = "???"
            else:
                time_per_detection = elapsed_timedelta / len_output
                remaining_time = (
                    len_input + len_current / (2 * self.config.num_containers)
                ) * time_per_detection
                remaining_time -= datetime.timedelta(
                    microseconds=remaining_time.microseconds
                )

            elapsed_timedelta -= datetime.timedelta(
                microseconds=elapsed_timedelta.microseconds
            )
            print(
                f"{len(self.sync_obj.outputQueue)} of {total_num_detections} in {elapsed_timedelta}, {remaining_time} remaining"
            )

    def showResults(self):
        pass

    def createReport(self):
        pass

    def stop(self):
        print("stopping cli")
        pass
