from splunk_contentctl.actions.detection_testing.newModules.DetectionTestingViewController import (
    DetectionTestingViewController,
)


class DetectionTestingViewCLI(DetectionTestingViewController):
    def setup(self):
        pass

    def showStatus(self, elapsed_seconds: float):
        if elapsed_seconds < self.next_update:
            return

        # We have passed our interval, time to update
        self.next_update = elapsed_seconds + self.interval
        print("Print Update")

    def showResults(self):
        pass

    def createReport(self):
        pass

    def stop(self):
        print("stopping cli")
        pass
