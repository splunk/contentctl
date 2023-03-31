from contentctl.actions.detection_testing.views.DetectionTestingView import (
    DetectionTestingView,
)

class DetectionTestingViewWeb(DetectionTestingView):
   
    def showStatus(self):
        # Status updated on page load
        # get all the finished detections:

       
        summary_dict = self.getSummaryObject(
            test_model_fields=["success", "message", "sid_link"]
        )

        currentTestingQueue=self.sync_obj.currentTestingQueue,
        percent_complete=summary_dict.get("percent_complete", 0),
        detections=summary_dict["tested_detections"],
        

        return 
