import queue
import time
from contentctl.actions.detection_testing.views.DetectionTestingView import (
    DetectionTestingView,
)

container_data = queue.Queue()
container_status = queue.Queue()

class DetectionTestingViewWeb(DetectionTestingView):

    def setup(self):
        # Status updated on page load
        # get all the finished detections:
       
        summary_dict = self.getSummaryObject(
            test_model_fields=["success", "message", "sid_link"]
        )
        # container_status.put(True)
        # status = container_status.get(block=False)
        if self.sync_obj.terminate:
            status = False
        else:
            status = True
        print(status)
        while status:
            try:
                if self.sync_obj.terminate == True:
                    status = False
                container_data.put({'currentTestingQueue': self.sync_obj.currentTestingQueue,
                                    'percent_complete': summary_dict.get("percent_complete", 0),
                                    'detections': summary_dict["tested_detections"],
                                    })
                time.sleep(1)
            except queue.Empty:
                pass
        print(f"instance status is {status}")
        
   
   