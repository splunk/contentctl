from contentctl.actions.detection_testing.views.DetectionTestingView import (
    DetectionTestingView,
)

import time
import tqdm


class DetectionTestingViewCLI(DetectionTestingView, arbitrary_types_allowed=True):
    pbar: tqdm.tqdm = None
    previous_output_queue_length: int = 0

    def format_pbar(self, completed_detections: int, total_detections: int):
        ratio = f"{completed_detections}/{total_detections}".ljust(9)
        try:
            et = str(self.getRuntime()).ljust(8)
        except Exception as e:
            et = str(e).ljust(8)

        try:
            etr = str(self.getETA()).ljust(8)
        except Exception as e:
            etr = str(e).ljust(8)

        bar = "{percentage:3.2f}%[{bar:30}]"
        self.pbar.bar_format = (
            f"Completed {ratio} {bar} | Elapsed: {et} | Remaining: {etr}"
        )
        self.pbar.reset(total=total_detections)
        self.pbar.update(completed_detections)

    def setup(self):
        self.previous_output_queue_length = len(self.sync_obj.outputQueue)
        self.pbar = tqdm.tqdm(
            total=len(self.sync_obj.inputQueue),
            initial=0,
            bar_format="",
            miniters=0,
            mininterval=0,
        )
        self.format_pbar(len(self.sync_obj.outputQueue), len(self.sync_obj.inputQueue))

        self.showStatus()

    # TODO (#267): Align test reporting more closely w/ status enums (as it relates to "untested")
    def showStatus(self, interval: int = 1):
        while True:
            summary = self.getSummaryObject()

            # TODO (#338): there's a 1-off error here I think (we show one more than we
            #   actually have during testing)
            total = len(
                summary.get("tested_detections", [])
                + summary.get("untested_detections", [])
                + self.getCurrent()
            )
            self.format_pbar(len(summary.get("tested_detections", [])), total)

            for _ in range(interval):
                if self.sync_obj.terminate:
                    return
                time.sleep(1)

    def showResults(self):
        pass

    def createReport(self):
        pass

    def stop(self):
        self.pbar.close()
        pass
