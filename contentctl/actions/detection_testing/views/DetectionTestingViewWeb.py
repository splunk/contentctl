import queue
from contentctl.actions.detection_testing.views.DetectionTestingView import (
    DetectionTestingView,
)

container_data = queue.Queue()

class DetectionTestingViewWeb(DetectionTestingView):

    def setup(self):
        # Status updated on page load
        # get all the finished detections:

       
        summary_dict = self.getSummaryObject(
            test_model_fields=["success", "message", "sid_link"]
        )
        update = True
        while update:
            try:
                container_data.put({'currentTestingQueue': self.sync_obj.currentTestingQueue,
                                    'percent_complete': summary_dict.get("percent_complete", 0),
                                    'detections': summary_dict["tested_detections"],
                                    })
            except queue.Empty:
                update = False

        
   
   