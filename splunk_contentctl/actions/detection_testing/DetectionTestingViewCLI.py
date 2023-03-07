from splunk_contentctl.actions.detection_testing.DetectionTestingView import (
    DetectionTestingView,
)

import time
import datetime
import tqdm


class DetectionTestingViewCLI(DetectionTestingView, arbitrary_types_allowed=True):
    pbar: tqdm.tqdm = None
    previous_output_queue_length: int = 0

    def format_pbar(
        self,
        completed_detections,
        total_detections,
        elapsed_time,
        estimated_time_remaining,
    ) -> str:
        ratio = f"{completed_detections}/{total_detections}".ljust(9)

        et = f"{elapsed_time}".ljust(8)
        etr = f"{estimated_time_remaining}".ljust(8)
        bar = "{percentage:3.0f}%[{bar:30}]"
        return f"Completed {ratio} {bar} | Elapsed: {et} | Remaining: {etr}"

    def setup(self):
        self.previous_output_queue_length = len(self.sync_obj.outputQueue)
        fmt = self.format_pbar(
            len(self.sync_obj.outputQueue), len(self.sync_obj.inputQueue), "TBD", "TBD"
        )
        self.pbar = tqdm.tqdm(
            total=len(self.sync_obj.inputQueue),
            initial=0,
            bar_format=fmt,
        )

        self.showStatus()

    def showStatus(self, interval: int = 10):
        while True:
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

            if self.sync_obj.start_time is None:
                time_string = self.format_pbar(
                    len_output, total_num_detections, "TBD", "TBD"
                )
            else:
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

                time_string = self.format_pbar(
                    len_output, total_num_detections, elapsed_timedelta, remaining_time
                )

            self.pbar.bar_format = time_string
            if len_output != self.previous_output_queue_length:
                update_diff = len_output - self.previous_output_queue_length
                self.previous_output_queue_length = len_output
                self.pbar.update(update_diff)

            else:
                self.pbar.update()

            for i in range(interval):
                if self.sync_obj.terminate:
                    print("Detection Testing Completed")
                    return
                time.sleep(1)

    def showResults(self):
        pass

    def createReport(self):
        pass

    def stop(self):
        self.pbar.close()
        pass
